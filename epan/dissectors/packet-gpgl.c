/* packet-gpgl.c
 * Routines for Graphtec Plotter Graphics Language (GP-GL) dissection
 * Copyright 2018, D. Bajar <david.bajar@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// TODO: Display coordinates in SU and mm (FF, FC)
// TODO: Add definitions for graphtec plotters
// TODO: Add dissector per plotter device
// TODO: Colouring for info section
// TODO: Heuristics
// TODO: Follow stream
// TODO: Integration with SVG viewer
// TODO: Add preference/option to swap x,y
// TODO: Add preference/option for imperial vs metric
// TODO: Add preference/option to 'hide' delimiters

/*
 * GP-GL is the protocol used to communicate with Graphtec plotters.
 */

#include <config.h>

#include <stdio.h>
#include <ctype.h>

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/expert.h>   /* Include only as needed */
#include <epan/prefs.h>    /* Include only as needed */
#include <epan/dissectors/packet-usb.h>
#include <wsutil/strtoi.h>

#define COMMANDS_IN_SUMMARY 10
#define RESPONSES_IN_SUMMARY 2
#define COORDS_IN_SUMMARY 3

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_gpgl(void);
void proto_register_gpgl(void);

/* Initialize the protocol and registered fields */
static int proto_gpgl = -1;

static int proto_gpgl_command_status_request = -1;
static int proto_gpgl_command_0B00 = -1;
static int proto_gpgl_command_get_device_info = -1;
static int proto_gpgl_command_TB71 = -1;
static int proto_gpgl_command_FA = -1;
static int proto_gpgl_command_TC = -1;
static int proto_gpgl_command_select_cutting_mat = -1;
static int proto_gpgl_command_FN = -1;
static int proto_gpgl_command_set_orientation = -1;
static int proto_gpgl_command_set_upper_bound = -1;
static int proto_gpgl_command_set_lower_bound = -1;
static int proto_gpgl_command_select_tool_holder = -1;
static int proto_gpgl_command_set_speed = -1;
static int proto_gpgl_command_set_pressure = -1;
static int proto_gpgl_command_set_overcut = -1;
static int proto_gpgl_command_set_overcut_offset = -1;
static int proto_gpgl_command_set_blade_offset = -1;
static int proto_gpgl_command_set_auto_blade = -1;
static int proto_gpgl_command_set_line_type = -1;
static int proto_gpgl_command_move_abs = -1;
static int proto_gpgl_command_move_rel = -1;
static int proto_gpgl_command_draw_abs = -1;
static int proto_gpgl_command_draw_rel = -1;
static int proto_gpgl_command_bdraw_abs = -1;
static int proto_gpgl_command_bdraw_rel = -1;
static int proto_gpgl_command_unknown = -1;
static int proto_gpgl_command_coord = -1;
static int proto_gpgl_command_coord_x = -1;
static int proto_gpgl_command_coord_y = -1;

static int proto_gpgl_response_status_response = -1;
static int proto_gpgl_response_generic = -1;

static int hf_gpgl_command_btype = -1;
static int hf_gpgl_command_type = -1;
static int hf_gpgl_command_delim = -1;
static int hf_gpgl_command_0B00_arg = -1;
static int hf_gpgl_command_tb_arg = -1;
static int hf_gpgl_command_cutting_mat_type = -1;
static int hf_gpgl_command_fn_arg = -1;
static int hf_gpgl_command_orientation_type = -1;
static int hf_gpgl_command_set_bound_x = -1;
static int hf_gpgl_command_set_bound_y = -1;
static int hf_gpgl_command_tool_holder_num = -1;
static int hf_gpgl_command_set_speed_speed = -1;
static int hf_gpgl_command_set_pressure_pressure = -1;
static int hf_gpgl_command_set_overcut_state = -1;
static int hf_gpgl_command_set_overcut_offset_x = -1;
static int hf_gpgl_command_set_overcut_offset_y = -1;
static int hf_gpgl_command_set_blade_offset_r = -1;
static int hf_gpgl_command_set_blade_offset_arg = -1;
static int hf_gpgl_command_set_auto_blade_depth = -1;
static int hf_gpgl_command_set_line_type_arg = -1;
static int hf_gpgl_command_move_x = -1;
static int hf_gpgl_command_move_y = -1;
static int hf_gpgl_command_draw_x = -1;
static int hf_gpgl_command_draw_y = -1;

static int hf_gpgl_response_type = -1;
static int hf_gpgl_response_generic_text = -1;

/* Initialize the subtree pointers */
static gint ett_gpgl = -1;
static gint ett_gpgl_command = -1;
static gint ett_gpgl_command_coord = -1;
static gint ett_gpgl_response = -1;

static dissector_handle_t gpgl_bulk_handle;

/* Booleans */
#define GPGL_FEATURE_DISABLED   '0'  /* Disable feature */
#define GPGL_FEATURE_ENABLED    '1'  /* Enable feature */

static const value_string feature_state_vs[] = {
    { GPGL_FEATURE_DISABLED, "disabled" },
    { GPGL_FEATURE_ENABLED, "enabled" },
    { 0, NULL }
};

/* Orientation types */
#define GPGL_ORIENTATION_PORTRAIT   '0'  /* Portrait */
#define GPGL_ORIENTATION_LANDSCAPE  '1'  /* Landscape */

static const value_string orientation_type_vs[] = {
    { GPGL_ORIENTATION_PORTRAIT, "portrait" },
    { GPGL_ORIENTATION_LANDSCAPE, "landscape" },
    { 0, NULL }
};

/* Cutting mat types */
#define GPGL_CUTTING_MAT_NONE   '0'  /* No cutting mat */
#define GPGL_CUTTING_MAT_12x12  '1'  /* 12x12in cutting mat */
#define GPGL_CUTTING_MAT_12x24  '2'  /* 12x24in cutting mat */

static const value_string cutting_mat_type_vs[] = {
    { GPGL_CUTTING_MAT_NONE, "none" },
    { GPGL_CUTTING_MAT_12x12, "12x12in" },
    { GPGL_CUTTING_MAT_12x24, "12x24in" },
    { 0, NULL }
};

/* Tool holders */
#define GPGL_TOOL_HOLDER_NONE   '0'  /* None (reset) */
#define GPGL_TOOL_HOLDER_LEFT   '1'  /* Left tool holder (red) */
#define GPGL_TOOL_HOLDER_RIGHT  '2'  /* Right tool holder (blue) */

static const value_string tool_holder_num_vs[] = {
    { GPGL_TOOL_HOLDER_NONE, "none[reset]" },
    { GPGL_TOOL_HOLDER_LEFT, "left[red]" },
    { GPGL_TOOL_HOLDER_RIGHT, "right[blue]" },
    { 0, NULL }
};

/* Responses */
#define GPGL_RESPONSE_READY     '0'  /* Ready */
#define GPGL_RESPONSE_MOVING    '1'  /* Moving */
#define GPGL_RESPONSE_PAUSED    '3'  /* Paused */
#define GPGL_RESPONSE_CANCELLED '4'  /* Cancelled */

static const value_string response_type_vs[] = {
    { GPGL_RESPONSE_READY, "ready" },
    { GPGL_RESPONSE_MOVING, "moving" },
    { GPGL_RESPONSE_PAUSED, "paused" },
    { GPGL_RESPONSE_CANCELLED, "cancelled" },
    { 0, NULL }
};

typedef struct arg_struct {
    int hf;
    const value_string *vstr;
    field_display_e btype;
} arg_struct;

static int
strtoi32(tvbuff_t *tvb, int offset, int length, gint32 *value)
{
    const char *str, *end_str;

    str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_UTF_8|ENC_NA);

    if(!ws_strtoi32(str, &end_str, value)) {
        return(-1);
    }
    return(end_str - str);
}

static int
dissect_gpgl_arg(proto_tree *tree, tvbuff_t *tvb, int offset, int length, arg_struct *arg, char *arg_buf, int arg_buf_len, char *arg_prefix)
{
    int arg_offset;
    int delim_offset;

    arg_offset = offset;
    if(arg->vstr != NULL) {
        proto_tree_add_item(tree, arg->hf, tvb, offset, 1, ENC_NA);
        if(arg_buf != NULL) {
            gint8 value = tvb_get_guint8(tvb, offset);
            snprintf(arg_buf, arg_buf_len, "%s%s", arg_prefix, val_to_str(value, arg->vstr, "Unknown (%d)"));
        }
        offset++;
        length--;
    } else {
        if(arg->btype == BASE_DEC) {
            // TODO: Convert to int using strtoi32 to find real end
            int d_offset = tvb_find_guint8(tvb, offset, length, ',');
            int a_len = d_offset < 0 ? length : d_offset - offset;
            proto_tree_add_item(tree, arg->hf, tvb, offset, a_len, ENC_NA);
            if(arg_buf != NULL) {
                guint8 *value = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, a_len, ENC_UTF_8);
                snprintf(arg_buf, arg_buf_len, "%s%s", arg_prefix, value);
            }
            offset += a_len;
            length -= a_len;
        } else if(arg->btype == BASE_HEX) {
            int d_offset = tvb_find_guint8(tvb, offset, length, ',');
            int a_len = d_offset < 0 ? length : d_offset - offset;
            proto_tree_add_item(tree, arg->hf, tvb, offset, a_len, ENC_NA);
            if(arg_buf != NULL) {
                gchar *value = tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, a_len);
                snprintf(arg_buf, arg_buf_len, "%s\\x%s", arg_prefix, value);
            }
            offset += a_len;
            length -= a_len;
        } else {
            int d_offset = tvb_find_guint8(tvb, offset, length, ',');
            int a_len = d_offset < 0 ? length : d_offset - offset;
            proto_tree_add_item(tree, arg->hf, tvb, offset, a_len, ENC_NA);
            if(arg_buf != NULL) {
                guint8 *value = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, a_len, ENC_UTF_8);
                snprintf(arg_buf, arg_buf_len, "%s'%s'", arg_prefix, value);
            }
            offset += a_len;
            length -= a_len;
        }
    }

    delim_offset = tvb_find_guint8(tvb, offset, length, ',');
    if(delim_offset > 0) {
        // TODO: Log junk after arg
    }

    if(delim_offset < 0) {
        if(length > 0) {
            // TODO: Log junk after arg
        }
        offset += length;
    } else {
        offset = delim_offset + 1;
    }

    return(offset - arg_offset);
}

static void
dissect_gpgl_command_args(proto_tree *tree, tvbuff_t *tvb, int offset, int length, gboolean binary, int type_length, int proto, arg_struct *args, packet_info *pinfo)
{
    proto_item *field_item;
    proto_tree *field_tree;
    int num_args = 0;
    char arg_str[120] = { '\0' };
    char *prefix, *suffix;

    field_item = proto_tree_add_item(tree, proto, tvb, offset, length, ENC_NA);
    field_tree = proto_item_add_subtree(field_item, ett_gpgl_command);

    proto_tree_add_item(field_tree, !binary ? hf_gpgl_command_type : hf_gpgl_command_btype, tvb, offset, type_length, ENC_NA);
    offset += type_length;
    length -= type_length;

    if(!binary) {
        length--;
    }

    while(args != NULL && args->hf != -1) {

        int str_len = strlen(arg_str);
        char *a_str = arg_str + str_len;
        int a_str_len = sizeof(arg_str) - str_len;
        int arg_length;

        arg_length = dissect_gpgl_arg(field_tree, tvb, offset, length, args, a_str, a_str_len, num_args > 0 ? ", " : "");
        if(arg_length < 0) {
            break;
        }

        offset += arg_length;
        length -= arg_length;
        num_args++;
        args++;
    }

    if(!binary) {
        length++;
    }

    prefix = num_args > 0 ? (num_args > 1 ? ": (" : ": ") : "";
    suffix = num_args > 1 ? ")" : "";
    proto_item_append_text(field_item, ": %s", arg_str);

    if(length > 0) {
        if(tvb_get_guint8(tvb, offset + length - 1) == 0x03) {
            proto_tree_add_item(field_tree, hf_gpgl_command_delim, tvb, offset + length - 1, 1, ENC_NA);
            length -= 1;
        }
        if(length > 0) {
            // TODO: Log junk at end of command
        }
    }

    if(pinfo != NULL) {
        proto_item_append_text(tree, ", %s%s%s%s", proto_get_protocol_short_name(find_protocol_by_id(proto)), prefix, arg_str, suffix);
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s%s%s", proto_get_protocol_short_name(find_protocol_by_id(proto)), prefix, arg_str, suffix);
    }
}

static int
dissect_gpgl_coord(proto_tree *tree, tvbuff_t *tvb, int offset, int length, char *coord_buf, int coord_buf_len, char *coord_prefix)
{
    proto_item *field_item, *coord_item_x, *coord_item_y;
    proto_tree *field_tree;
    int x_offset, y_offset;
    int x_length, y_length;
    int x = 0, y = 0;
    int delim_offset;

    x_offset = offset;
    x_length = strtoi32(tvb, offset, length, &x);
    if(x_length < 0) {
        // TODO: Log x not found
        return(-1);
    }
    offset += x_length;
    length -= x_length;

    delim_offset = tvb_find_guint8(tvb, offset, length, ',');
    if(delim_offset < 0) {
        // TODO: Log ',' delim not found
        return(-1);
    }
    if(delim_offset > 0) {
        // TODO: Log junk after x
    }
    length -= delim_offset - offset + 1;
    offset = delim_offset + 1;

    y_offset = offset;
    y_length = strtoi32(tvb, offset, length, &y);
    if(y_length < 0) {
        // TODO: Log y not found
        return(-1);
    }
    offset += y_length;
    length -= y_length;

    delim_offset = tvb_find_guint8(tvb, offset, length, ',');
    if(delim_offset > 0) {
        // TODO: Log junk after y
    }

    if(delim_offset < 0) {
        if(length > 0) {
            // TODO: Log junk after y
        }
        offset += length;
    } else {
        offset = delim_offset + 1;
    }

    field_item = proto_tree_add_item(tree, proto_gpgl_command_coord, tvb, x_offset, offset - x_offset, ENC_NA);
    proto_item_append_text(field_item, " [mm]: %g,%g", x * 0.05, y * 0.05);
    field_tree = proto_item_add_subtree(field_item, ett_gpgl_command_coord);
    coord_item_x = proto_tree_add_item(field_tree, proto_gpgl_command_coord_x, tvb, x_offset, x_length, ENC_NA);
    proto_item_append_text(coord_item_x, "%g mm (%d SU)", x * 0.05, x);
    coord_item_y = proto_tree_add_item(field_tree, proto_gpgl_command_coord_y, tvb, y_offset, y_length, ENC_NA);
    proto_item_append_text(coord_item_y, "%g mm (%d SU)", y * 0.05, y);

    if(coord_buf != NULL) {
        snprintf(coord_buf, coord_buf_len, "%s%g,%g", coord_prefix, x * 0.05, y * 0.05);
    }

    return(offset - x_offset);
}

static void
dissect_gpgl_command_coord(proto_tree *tree, tvbuff_t *tvb, int offset, int length, int type_length, int proto, packet_info *pinfo)
{
    proto_item *field_item;
    proto_tree *field_tree;
    int num_coords = 0;
    char coord_str[40 * (COORDS_IN_SUMMARY + 1)] = { '\0' };
    char *prefix, *suffix;

    field_item = proto_tree_add_item(tree, proto, tvb, offset, length, ENC_NA);
    field_tree = proto_item_add_subtree(field_item, ett_gpgl_command);

    proto_tree_add_item(field_tree, hf_gpgl_command_type, tvb, offset, type_length, ENC_NA);
    offset += type_length;
    length -= type_length;

    while(length > 1) {

        char *c_str = NULL;
        int c_str_len = 0;
        int coord_length;

        if(num_coords < COORDS_IN_SUMMARY) {
            int str_len = strlen(coord_str);
            c_str = coord_str + str_len;
            c_str_len = sizeof(coord_str) - str_len;
        }

        coord_length = dissect_gpgl_coord(field_tree, tvb, offset, length - 1, c_str, c_str_len, num_coords > 0 ? " " : "");
        if(coord_length < 0) {
            break;
        }

        offset += coord_length;
        length -= coord_length;
        num_coords++;
    }

    prefix = num_coords > 0 ? "[mm]: (" : "";
    suffix = num_coords > 0 ? ")" : "";
    if(num_coords > COORDS_IN_SUMMARY) {
        int str_len = strlen(coord_str);
        snprintf(coord_str + str_len, sizeof(coord_str) - str_len, ", %d more coord(s)", num_coords - COORDS_IN_SUMMARY);
    }
    proto_item_append_text(field_item, "%s%s%s", prefix, coord_str, suffix);

    if(length > 0) {
        if(tvb_get_guint8(tvb, offset + length - 1) == 0x03) {
            proto_tree_add_item(field_tree, hf_gpgl_command_delim, tvb, offset + length - 1, 1, ENC_NA);
            length -= 1;
        }
        if(length > 0) {
            // TODO: Log junk at end of command
        }
    }

    if(pinfo != NULL) {
        proto_item_append_text(tree, ", %s%s%s%s", proto_get_protocol_short_name(find_protocol_by_id(proto)), prefix, coord_str, suffix);
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s%s%s", proto_get_protocol_short_name(find_protocol_by_id(proto)), prefix, coord_str, suffix);
    }
}

static int
benc_scheme_arg_length(int enc_scheme)
{
    switch(enc_scheme) {
        case 1:     return(2);
        case 2:     return(3);
        case 3:     return(5);
        default:    return(-1);
    }
}

static int
benc_scheme_decode(int enc_scheme, tvbuff_t *tvb, int offset, int *x, int *y)
{
    switch(enc_scheme) {
        case 1: {
            guint32 index;
            guint8 b1 = tvb_get_guint8(tvb, offset + 0);
            guint8 b2 = tvb_get_guint8(tvb, offset + 1);
            if(b1 < 0x20 || b2 < 0x20) {
                // TODO: Log bad encoding value(s)
            }
            index = (b2 - 0x20) * 224 + (b1 - 0x20);
            *x = index / 224 - 112;
            *y = index % 224 - 112;
            return(2);
        }
        case 2: {
            guint32 index;
            guint8 b1 = tvb_get_guint8(tvb, offset + 0);
            guint8 b2 = tvb_get_guint8(tvb, offset + 1);
            guint8 b3 = tvb_get_guint8(tvb, offset + 2);
            if(b1 < 0x20 || b2 < 0x20 || b3 < 0x20) {
                // TODO: Log bad encoding value(s)
            }
            index = (b3 - 0x20) * (224 * 224) + (b2 - 0x20) * 224 + (b1 - 0x20);
            *x = index / 3352 - 1676;
            *y = index % 3352 - 1676;
            return(3);
        }
        case 3: {
            guint64 index;
            guint8 b1 = tvb_get_guint8(tvb, offset + 0);
            guint8 b2 = tvb_get_guint8(tvb, offset + 1);
            guint8 b3 = tvb_get_guint8(tvb, offset + 2);
            guint8 b4 = tvb_get_guint8(tvb, offset + 3);
            guint8 b5 = tvb_get_guint8(tvb, offset + 4);
            if(b1 < 0x20 || b2 < 0x20 || b3 < 0x20 || b4 < 0x20 || b5 < 0x20) {
                // TODO: Log bad encoding value(s)
            }
            index = (b5 - 0x20L) * (224L * 224 * 224 * 224) + (b4 - 0x20) * (224 * 224 * 224) + (b3 - 0x20) * (224 * 224) + (b2 - 0x20) * 224 + (b1 - 0x20);
            *x = index / 750964 - 375482;
            *y = index % 750964 - 375482;
            return(5);
        }
        default:
            return(-1);
    }
}

static void
dissect_gpgl_command_binary(proto_tree *tree, tvbuff_t *tvb, int offset, int length, int type_length, int proto, int enc_scheme, packet_info *pinfo)
{
    proto_item *field_item;
    proto_tree *field_tree;
    int coord_length;
    int num_coords = 0;
    char coord_str[40 * (COORDS_IN_SUMMARY + 1)] = { '\0' };
    char *prefix, *suffix;

    field_item = proto_tree_add_item(tree, proto, tvb, offset, length, ENC_NA);
    field_tree = proto_item_add_subtree(field_item, ett_gpgl_command);

    proto_tree_add_item(field_tree, hf_gpgl_command_type, tvb, offset, type_length, ENC_NA);
    offset += type_length;
    length -= type_length;

    coord_length = benc_scheme_arg_length(enc_scheme);

    while(length > coord_length) {
        proto_item *coord_item, *coord_item_x, *coord_item_y;
        proto_tree *coord_tree;
        int x = 0, y = 0;

        benc_scheme_decode(enc_scheme, tvb, offset, &x, &y);

        coord_item = proto_tree_add_item(field_tree, proto_gpgl_command_coord, tvb, offset, coord_length, ENC_NA);
        proto_item_append_text(coord_item, " [mm]: %g,%g", x * 0.05, y * 0.05);
        coord_tree = proto_item_add_subtree(coord_item, ett_gpgl_command_coord);
        coord_item_x = proto_tree_add_item(coord_tree, proto_gpgl_command_coord_x, tvb, offset, coord_length, ENC_NA);
        proto_item_append_text(coord_item_x, "%g mm (%d SU)", x * 0.05, x);
        coord_item_y = proto_tree_add_item(coord_tree, proto_gpgl_command_coord_y, tvb, offset, coord_length, ENC_NA);
        proto_item_append_text(coord_item_y, "%g mm (%d SU)", y * 0.05, y);

        if(num_coords < COORDS_IN_SUMMARY) {
            int str_len = strlen(coord_str);
            snprintf(coord_str + str_len, sizeof(coord_str) - str_len, "%s%g,%g", num_coords > 0 ? " " : "", x * 0.05, y * 0.05);
        }

        offset += coord_length;
        length -= coord_length;
        num_coords++;
    }

    prefix = num_coords > 0 ? "[mm]: (" : "";
    suffix = num_coords > 0 ? ")" : "";
    if(num_coords > COORDS_IN_SUMMARY) {
        int str_len = strlen(coord_str);
        snprintf(coord_str + str_len, sizeof(coord_str) - str_len, ", %d more coords", num_coords - COORDS_IN_SUMMARY);
    }
    proto_item_append_text(field_item, "%s%s%s", prefix, coord_str, suffix);

    if(length > 0) {
        if(tvb_get_guint8(tvb, offset + length - 1) == 0x03) {
            proto_tree_add_item(field_tree, hf_gpgl_command_delim, tvb, offset + length - 1, 1, ENC_NA);
            length -= 1;
        }
        if(length > 0) {
            // TODO: Log junk at end of command
        }
    }

    if(pinfo != NULL) {
        proto_item_append_text(tree, ", %s%s%s%s", proto_get_protocol_short_name(find_protocol_by_id(proto)), prefix, coord_str, suffix);
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s%s%s", proto_get_protocol_short_name(find_protocol_by_id(proto)), prefix, coord_str, suffix);
    }
}

static int
dissect_gpgl_command_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint offset = 0;
    int num_commands = 0;

    if(tvb_captured_length(tvb) == 2 && tvb_get_ntohs(tvb, 0) == 0x1b05) {
        dissect_gpgl_command_args(tree, tvb, 0, 2, TRUE, 2, proto_gpgl_command_status_request, NULL, pinfo);
        return(2);
    }

    if(tvb_captured_length(tvb) == 3 && tvb_get_ntohs(tvb, 0) == 0x1b00) {
        arg_struct args[] = {
            { hf_gpgl_command_0B00_arg, NULL, BASE_HEX },
            { -1, NULL, BASE_NONE }
        };
        dissect_gpgl_command_args(tree, tvb, 0, 3, TRUE, 2, proto_gpgl_command_0B00, args, pinfo);
        return(3);
    }

    while(offset < tvb_captured_length(tvb)) {

        gint delim_offset;
        guint8 *command;
        packet_info *p_in = num_commands < COMMANDS_IN_SUMMARY ? pinfo : NULL;

        delim_offset = tvb_find_guint8(tvb, offset, -1, 0x03);
        if(delim_offset < 0) {
            if(tvb_captured_length(tvb) != tvb_reported_length(tvb)) {
                // TODO: Log junk at end of command
            }
            break;
        }

        if(num_commands > 0) {
            col_append_str(pinfo->cinfo, COL_INFO, ", ");
        }

        command = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, delim_offset - offset, ENC_UTF_8);
        if(!strncmp("FG", command, 2)) {
            dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 2, proto_gpgl_command_get_device_info, NULL, p_in);
        } else if(!strncmp("TB", command, 2)) {
            if(!strncmp("71", &command[2], 2)) {
                dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 4, proto_gpgl_command_TB71, NULL, p_in);
            } else if(!strncmp("50", &command[2], 2)) {
                arg_struct args[] = {
                    { hf_gpgl_command_tb_arg, NULL, BASE_NONE },
                    { hf_gpgl_command_orientation_type, orientation_type_vs, BASE_NONE },
                    { -1, NULL, BASE_NONE }
                };
                dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 2, proto_gpgl_command_set_orientation, args, p_in);
            }
        } else if(!strncmp("FA", command, 2)) {
            dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 2, proto_gpgl_command_FA, NULL, p_in);
        } else if(!strncmp("TC", command, 2)) {
            dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 2, proto_gpgl_command_TC, NULL, p_in);
        } else if(!strncmp("TG", command, 2)) {
            arg_struct args[] = {
                { hf_gpgl_command_cutting_mat_type, cutting_mat_type_vs, BASE_NONE },
                { -1, NULL, BASE_NONE }
            };
            dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 2, proto_gpgl_command_select_cutting_mat, args, p_in);
        } else if(!strncmp("FN", command, 2)) {
            arg_struct args[] = {
                { hf_gpgl_command_fn_arg, NULL, BASE_NONE },
                { -1, NULL, BASE_NONE }
            };
            dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 2, proto_gpgl_command_FN, args, p_in);
        } else if(!strncmp("\\", command, 1)) {
            dissect_gpgl_command_coord(tree, tvb, offset, delim_offset - offset + 1, 1, proto_gpgl_command_set_upper_bound, p_in);
        } else if(!strncmp("Z", command, 1)) {
            dissect_gpgl_command_coord(tree, tvb, offset, delim_offset - offset + 1, 1, proto_gpgl_command_set_lower_bound, p_in);
        } else if(!strncmp("J", command, 1)) {
            arg_struct args[] = {
                { hf_gpgl_command_tool_holder_num, tool_holder_num_vs, BASE_NONE },
                { -1, NULL, BASE_NONE }
            };
            dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 1, proto_gpgl_command_select_tool_holder, args, p_in);
        } else if(!strncmp("!", command, 1)) {
            arg_struct args[] = {
                { hf_gpgl_command_set_speed_speed, NULL, BASE_DEC },
                { hf_gpgl_command_tool_holder_num, tool_holder_num_vs, BASE_NONE },
                { -1, NULL, BASE_NONE }
            };
            dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 1, proto_gpgl_command_set_speed, args, p_in);
        } else if(!strncmp("FX", command, 2)) {
            arg_struct args[] = {
                { hf_gpgl_command_set_pressure_pressure, NULL, BASE_DEC },
                { hf_gpgl_command_tool_holder_num, tool_holder_num_vs, BASE_NONE },
                { -1, NULL, BASE_NONE }
            };
            dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 2, proto_gpgl_command_set_pressure, args, p_in);
        } else if(!strncmp("FE", command, 2)) {
            arg_struct args[] = {
                { hf_gpgl_command_set_overcut_state, feature_state_vs, BASE_NONE },
                { hf_gpgl_command_tool_holder_num, tool_holder_num_vs, BASE_NONE },
                { -1, NULL, BASE_NONE }
            };
            dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 2, proto_gpgl_command_set_overcut, args, p_in);
        } else if(!strncmp("FF", command, 2)) {
            arg_struct args[] = {
                { hf_gpgl_command_set_overcut_offset_x, NULL, BASE_DEC },
                { hf_gpgl_command_set_overcut_offset_y, NULL, BASE_DEC },
                { hf_gpgl_command_tool_holder_num, tool_holder_num_vs, BASE_NONE },
                { -1, NULL, BASE_NONE }
            };
            dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 2, proto_gpgl_command_set_overcut_offset, args, p_in);
        } else if(!strncmp("FC", command, 2)) {
            arg_struct args[] = {
                { hf_gpgl_command_set_blade_offset_r, NULL, BASE_DEC },
                { hf_gpgl_command_set_blade_offset_arg, NULL, BASE_NONE },
                { hf_gpgl_command_tool_holder_num, tool_holder_num_vs, BASE_NONE },
                { -1, NULL, BASE_NONE }
            };
            dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 2, proto_gpgl_command_set_blade_offset, args, p_in);
        } else if(!strncmp("TF", command, 2)) {
            arg_struct args[] = {
                { hf_gpgl_command_set_auto_blade_depth, NULL, BASE_DEC },
                { hf_gpgl_command_tool_holder_num, tool_holder_num_vs, BASE_NONE },
                { -1, NULL, BASE_NONE }
            };
            dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 2, proto_gpgl_command_set_auto_blade, args, p_in);
        } else if(!strncmp("L", command, 1)) {
            arg_struct args[] = {
                { hf_gpgl_command_set_line_type_arg, NULL, BASE_NONE },
                { -1, NULL, BASE_NONE }
            };
            dissect_gpgl_command_args(tree, tvb, offset, delim_offset - offset + 1, FALSE, 1, proto_gpgl_command_set_line_type, args, p_in);
        } else if(!strncmp("M", command, 1)) {
            dissect_gpgl_command_coord(tree, tvb, offset, delim_offset - offset + 1, 1, proto_gpgl_command_move_abs, p_in);
        } else if(!strncmp("O", command, 1)) {
            dissect_gpgl_command_coord(tree, tvb, offset, delim_offset - offset + 1, 1, proto_gpgl_command_move_rel, p_in);
        } else if(!strncmp("D", command, 1)) {
            dissect_gpgl_command_coord(tree, tvb, offset, delim_offset - offset + 1, 1, proto_gpgl_command_draw_abs, p_in);
        } else if(!strncmp("E", command, 1)) {
            dissect_gpgl_command_coord(tree, tvb, offset, delim_offset - offset + 1, 1, proto_gpgl_command_draw_rel, p_in);
        } else if(!strncmp("BD1", command, 3)) {
            dissect_gpgl_command_binary(tree, tvb, offset, delim_offset - offset + 1, 3, proto_gpgl_command_bdraw_abs, 1, p_in);
        } else if(!strncmp("BD2", command, 3)) {
            dissect_gpgl_command_binary(tree, tvb, offset, delim_offset - offset + 1, 3, proto_gpgl_command_bdraw_abs, 2, p_in);
        } else if(!strncmp("BD3", command, 3)) {
            dissect_gpgl_command_binary(tree, tvb, offset, delim_offset - offset + 1, 3, proto_gpgl_command_bdraw_abs, 3, p_in);
        } else if(!strncmp("BE1", command, 3)) {
            dissect_gpgl_command_binary(tree, tvb, offset, delim_offset - offset + 1, 3, proto_gpgl_command_bdraw_rel, 1, p_in);
        } else if(!strncmp("BE2", command, 3)) {
            dissect_gpgl_command_binary(tree, tvb, offset, delim_offset - offset + 1, 3, proto_gpgl_command_bdraw_rel, 2, p_in);
        } else if(!strncmp("BE3", command, 3)) {
            dissect_gpgl_command_binary(tree, tvb, offset, delim_offset - offset + 1, 3, proto_gpgl_command_bdraw_rel, 3, p_in);
        } else {
            proto_tree_add_item(tree, proto_gpgl_command_unknown, tvb, offset, delim_offset - offset + 1, ENC_NA);
            if(num_commands < COMMANDS_IN_SUMMARY) {
                proto_item_append_text(tree, ", %s", proto_get_protocol_short_name(find_protocol_by_id(proto_gpgl_command_unknown)));
                col_append_str(pinfo->cinfo, COL_INFO, proto_get_protocol_short_name(find_protocol_by_id(proto_gpgl_command_unknown)));
            }
        }

        offset = delim_offset + 1;
        num_commands++;
    }

    if(num_commands <= 0) {
        proto_item_append_text(tree, ", Command");
        col_set_str(pinfo->cinfo, COL_INFO, "Command");
    } else if(num_commands > COMMANDS_IN_SUMMARY) {
        proto_item_append_text(tree, ", %d more command(s) ...", num_commands - COMMANDS_IN_SUMMARY);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %d more command(s) ...", num_commands - COMMANDS_IN_SUMMARY);
    }

    return(offset);
}

static int
dissect_gpgl_response_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *field_item;
    proto_tree *field_tree;
    guint offset = 0;
    int num_responses = 0;

    while(offset < tvb_captured_length(tvb)) {
        gint delim_offset;

        delim_offset = tvb_find_guint8(tvb, offset, -1, 0x03);
        if(delim_offset < 0) {
            if(tvb_captured_length(tvb) != tvb_reported_length(tvb)) {
                // TODO: Log junk at end of response
            }
            break;
        }

        if(num_responses > 0) {
            col_append_str(pinfo->cinfo, COL_INFO, ", ");
        }

        if(delim_offset - offset + 1 == 2) {
            guint8 value;
            field_item = proto_tree_add_item(tree, proto_gpgl_response_status_response, tvb, offset, 2, ENC_NA);
            field_tree = proto_item_add_subtree(field_item, ett_gpgl_response);
            proto_tree_add_item(field_tree, hf_gpgl_response_type, tvb, offset, 1, ENC_NA);
            value = tvb_get_guint8(tvb, offset);
            proto_item_append_text(field_item, ": %s", val_to_str(value, response_type_vs, "Unknown (%d)"));
            proto_tree_add_item(field_tree, hf_gpgl_command_delim, tvb, offset + 1, 1, ENC_NA);
            if(num_responses < RESPONSES_IN_SUMMARY) {
                proto_item_append_text(tree, ", %s: %s", proto_get_protocol_short_name(find_protocol_by_id(proto_gpgl_response_status_response)), val_to_str(value, response_type_vs, "Unknown (%d)"));
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s: %s", proto_get_protocol_short_name(find_protocol_by_id(proto_gpgl_response_status_response)), val_to_str(value, response_type_vs, "Unknown (%d)"));
            }
        } else {
            guint8 *response;
            field_item = proto_tree_add_item(tree, proto_gpgl_response_generic, tvb, offset, delim_offset - offset + 1, ENC_NA);
            field_tree = proto_item_add_subtree(field_item, ett_gpgl_response);
            proto_tree_add_item(field_tree, hf_gpgl_response_generic_text, tvb, offset, delim_offset - offset, ENC_NA);
            response = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, delim_offset - offset, ENC_UTF_8);
            proto_item_append_text(field_item, ": '%s'", response);
            proto_tree_add_item(field_tree, hf_gpgl_command_delim, tvb, delim_offset, 1, ENC_NA);
            if(num_responses < RESPONSES_IN_SUMMARY) {
                proto_item_append_text(tree, ", '%s'", response);
                col_append_fstr(pinfo->cinfo, COL_INFO, "'%s'", response);
            }
        }

        offset = delim_offset + 1;
        num_responses++;
    }

    if(num_responses <= 0) {
        proto_item_append_text(tree, ", Response");
        col_set_str(pinfo->cinfo, COL_INFO, "Response");
    } else if(num_responses > RESPONSES_IN_SUMMARY) {
        proto_item_append_text(tree, ", %d more response(s) ...", num_responses - RESPONSES_IN_SUMMARY);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %d more response(s) ...", num_responses - RESPONSES_IN_SUMMARY);
    }

    return(offset);
}

/* Code to actually dissect the packets */
static int
dissect_gpgl_bulk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti;
    proto_tree *gpgl_tree;
    usb_conv_info_t *usb_conv_info;
    guint8 length;

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_gpgl, tvb, 0, -1, ENC_NA);
    gpgl_tree = proto_item_add_subtree(ti, ett_gpgl);

    /* Set the Protocol column to the constant string of gpgl */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GP-GL");
    col_clear(pinfo->cinfo, COL_INFO);

    usb_conv_info = (usb_conv_info_t *) data;

    if(!usb_conv_info->direction) {
        length = dissect_gpgl_command_block(tvb, pinfo, gpgl_tree);
    } else {
        length = dissect_gpgl_response_block(tvb, pinfo, gpgl_tree);
    }

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return(length);
}

void
proto_register_gpgl(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_gpgl_command_btype, { "Type", "gpgl.command.btype", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_type, { "Type", "gpgl.command.type", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_delim, { "Delimiter", "gpgl.command.delim", FT_UINT8, BASE_HEX|BASE_EXT_STRING, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_0B00_arg, { "Arg", "gpgl.command.0b00.arg", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_tb_arg, { "Arg", "gpgl.command.tb.arg", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_cutting_mat_type, { "Cutting mat", "gpgl.command.cutting_mat.type", FT_CHAR, BASE_NONE, VALS(cutting_mat_type_vs), 0x0, NULL, HFILL } },
        { &hf_gpgl_command_fn_arg, { "Arg", "gpgl.command.fn.arg", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_orientation_type, { "Orientation", "gpgl.command.orientation.type", FT_CHAR, BASE_NONE, VALS(orientation_type_vs), 0x0, NULL, HFILL } },
        { &hf_gpgl_command_set_bound_x, { "X", "gpgl.command.set_bound.x", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_set_bound_y, { "Y", "gpgl.command.set_bound.y", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_tool_holder_num, { "Tool holder", "gpgl.command.tool_holder.num", FT_CHAR, BASE_NONE, VALS(tool_holder_num_vs), 0x0, NULL, HFILL } },
        { &hf_gpgl_command_set_speed_speed, { "Speed", "gpgl.command.set_speed.speed", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_set_pressure_pressure, { "Pressure", "gpgl.command.set_pressure.pressure", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_set_overcut_state, { "State", "gpgl.command.set_overcut.state", FT_CHAR, BASE_NONE, VALS(feature_state_vs), 0x0, NULL, HFILL } },
        { &hf_gpgl_command_set_overcut_offset_x, { "X", "gpgl.command.set_overcut_offset.x", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_set_overcut_offset_y, { "Y", "gpgl.command.set_overcut_offset.y", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_set_blade_offset_r, { "Radius", "gpgl.command.set_blade_offset.d", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_set_blade_offset_arg, { "Arg", "gpgl.command.set_blade_offset.arg", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_set_auto_blade_depth, { "Depth", "gpgl.command.set_auto_blade.depth", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_set_line_type_arg, { "Arg", "gpgl.command.set_line_type.arg", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_move_x, { "X", "gpgl.command.move.x", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_move_y, { "Y", "gpgl.command.move.y", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_draw_x, { "X", "gpgl.command.draw.x", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_command_draw_y, { "Y", "gpgl.command.draw.y", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_gpgl_response_type, { "Type", "gpgl.response.type", FT_CHAR, BASE_NONE, VALS(response_type_vs), 0x0, NULL, HFILL } },
        { &hf_gpgl_response_generic_text, { "Text", "gpgl.response.generic.text", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_gpgl,
        &ett_gpgl_command,
        &ett_gpgl_command_coord,
        &ett_gpgl_response,
    };

    /* Register the protocol name and description */
    proto_gpgl = proto_register_protocol("Graphtec Plotter Graphics Language",
            "GP-GL", "gpgl");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_gpgl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    gpgl_bulk_handle = register_dissector("gpgl", dissect_gpgl_bulk, proto_gpgl);

    /* Register GP-GL commands as their own protocols so we can get the name of the command */
    proto_gpgl_command_status_request = proto_register_protocol_in_name_only("GPGL Command - Status Request", "Status request", "gpgl.commands.status_request", proto_gpgl, FT_BYTES);
    proto_gpgl_command_0B00 = proto_register_protocol_in_name_only("GPGL Command - 0B00(?)", "0B00(?)", "gpgl.commands.0b00", proto_gpgl, FT_BYTES);
    proto_gpgl_command_get_device_info = proto_register_protocol_in_name_only("GPGL Command - Get Device Info", "Get device info", "gpgl.commands.get_device_info", proto_gpgl, FT_BYTES);
    proto_gpgl_command_TB71 = proto_register_protocol_in_name_only("GPGL Command - TB71(?)", "TB71(?)", "gpgl.commands.tb71", proto_gpgl, FT_BYTES);
    proto_gpgl_command_FA = proto_register_protocol_in_name_only("GPGL Command - FA(?)", "FA(?)", "gpgl.commands.fa", proto_gpgl, FT_BYTES);
    proto_gpgl_command_TC = proto_register_protocol_in_name_only("GPGL Command - TC(?)", "TC(?)", "gpgl.commands.tc", proto_gpgl, FT_BYTES);
    proto_gpgl_command_select_cutting_mat = proto_register_protocol_in_name_only("GPGL Command - Select Cutting Mat", "Select cutting mat", "gpgl.commands.select_cutting_mat", proto_gpgl, FT_BYTES);
    proto_gpgl_command_FN = proto_register_protocol_in_name_only("GPGL Command - FN(?)", "FN(?)", "gpgl.commands.fn", proto_gpgl, FT_BYTES);
    proto_gpgl_command_set_orientation = proto_register_protocol_in_name_only("GPGL Command - Set Orientation", "Set orientation", "gpgl.commands.set_orientation", proto_gpgl, FT_BYTES);
    proto_gpgl_command_set_upper_bound = proto_register_protocol_in_name_only("GPGL Command - Set Upper Bound", "Set upper bound", "gpgl.commands.set_upper_bound", proto_gpgl, FT_BYTES);
    proto_gpgl_command_set_lower_bound = proto_register_protocol_in_name_only("GPGL Command - Set Lower Bound", "Set lower bound", "gpgl.commands.set_lower_bound", proto_gpgl, FT_BYTES);
    proto_gpgl_command_select_tool_holder = proto_register_protocol_in_name_only("GPGL Command - Select Tool Holder", "Select tool holder", "gpgl.commands.select_tool_holder", proto_gpgl, FT_BYTES);
    proto_gpgl_command_set_speed = proto_register_protocol_in_name_only("GPGL Command - Set Speed", "Set speed", "gpgl.commands.set_speed", proto_gpgl, FT_BYTES);
    proto_gpgl_command_set_pressure = proto_register_protocol_in_name_only("GPGL Command - Set Pressure", "Set pressure", "gpgl.commands.set_pressure", proto_gpgl, FT_BYTES);
    proto_gpgl_command_set_overcut = proto_register_protocol_in_name_only("GPGL Command - Set Overcut", "Set overcut", "gpgl.commands.set_overcut", proto_gpgl, FT_BYTES);
    proto_gpgl_command_set_overcut_offset = proto_register_protocol_in_name_only("GPGL Command - Set Overcut Offset", "Set overcut offset", "gpgl.commands.set_overcut_offset", proto_gpgl, FT_BYTES);
    proto_gpgl_command_set_blade_offset = proto_register_protocol_in_name_only("GPGL Command - Set Blade Offset", "Set blade offset", "gpgl.commands.set_blade_offset", proto_gpgl, FT_BYTES);
    proto_gpgl_command_set_auto_blade = proto_register_protocol_in_name_only("GPGL Command - Set Auto-Blade", "Set auto-blade", "gpgl.commands.set_auto_blade", proto_gpgl, FT_BYTES);
    proto_gpgl_command_set_line_type = proto_register_protocol_in_name_only("GPGL Command - Set Line Type", "Set line type", "gpgl.commands.set_line_type", proto_gpgl, FT_BYTES);
    proto_gpgl_command_move_abs = proto_register_protocol_in_name_only("GPGL Command - Move (abs)", "Move (abs)", "gpgl.commands.move_abs", proto_gpgl, FT_BYTES);
    proto_gpgl_command_move_rel = proto_register_protocol_in_name_only("GPGL Command - Move (rel)", "Move (rel)", "gpgl.commands.move_rel", proto_gpgl, FT_BYTES);
    proto_gpgl_command_draw_abs = proto_register_protocol_in_name_only("GPGL Command - Draw (abs)", "Draw (abs)", "gpgl.commands.draw_abs", proto_gpgl, FT_BYTES);
    proto_gpgl_command_draw_rel = proto_register_protocol_in_name_only("GPGL Command - Draw (rel)", "Draw (rel)", "gpgl.commands.draw_rel", proto_gpgl, FT_BYTES);
    proto_gpgl_command_bdraw_abs = proto_register_protocol_in_name_only("GPGL Command - Binary Draw (abs)", "Binary draw (abs)", "gpgl.commands.bdraw_abs", proto_gpgl, FT_BYTES);
    proto_gpgl_command_bdraw_rel = proto_register_protocol_in_name_only("GPGL Command - Binary Draw (rel)", "Binary draw (rel)", "gpgl.commands.bdraw_rel", proto_gpgl, FT_BYTES);
    proto_gpgl_command_unknown = proto_register_protocol_in_name_only("GPGL Command - Unknown(?)", "Unknown(?)", "gpgl.commands.unknown", proto_gpgl, FT_BYTES);
    proto_gpgl_command_coord = proto_register_protocol_in_name_only("Coord", "Coord", "gpgl.commands.coord", proto_gpgl, FT_BYTES);
    proto_gpgl_command_coord_x = proto_register_protocol_in_name_only("X: ", "X: ", "gpgl.commands.coord.x", proto_gpgl, FT_BYTES);
    proto_gpgl_command_coord_y = proto_register_protocol_in_name_only("Y: ", "Y: ", "gpgl.commands.coord.y", proto_gpgl, FT_BYTES);
    proto_gpgl_response_status_response = proto_register_protocol_in_name_only("GPGL Response - Status Response", "Status response", "gpgl.responses.status_response", proto_gpgl, FT_BYTES);
    proto_gpgl_response_generic = proto_register_protocol_in_name_only("GPGL Response", "Response", "gpgl.responses.response", proto_gpgl, FT_BYTES);
}

void
proto_reg_handoff_gpgl(void)
{
    dissector_add_uint("usb.bulk", IF_CLASS_PRINTER, gpgl_bulk_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
