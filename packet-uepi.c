/**
 * @file
 * BCM3142/UEPI Packet dissector.
 */


#include "config.h"

#include <stdio.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <epan/packet.h>
#include <string.h>
#include <epan/prefs.h>
//#include "simple_dialog.h"
#include "uepi.h"

static gboolean uepi_dissect_flag = TRUE;
static module_t *uepi_module = NULL;

static gint debug_level = 1;
static dissector_handle_t docsis_mgmt_handle = NULL;
static dissector_handle_t data_handle = NULL;

/** Private info passed to subdissectors -- contains the UEPI header. */
static uepi_info_t uepi_info;

#if 1
    #define DEP( level, msg ) if ( level <= debug_level ) { g_printf msg; }
    /* Could also use: proto_tree_add_debug_text(tree, format) */
#else
    #define DEP( level, msg )
    /* proto_tree_add_debug_text(tree, format) */
    /* simple_dialog( ESD_TYPE_ERROR, ESD_BTN_OK, "Processing UEPI frame" ); */
#endif

#define PROTO_TAG_UEPI	"UEPI"

/* Wireshark ID of the UEPI protocol */
static int proto_uepi = -1;

static void dissect_uepi( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree );
static char *bitmaskToString( guint8 bits, guint32 mask );
static void dissect_uepi_segment( tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree, gint offset );

/*
 * The following hf_* variables are used to hold the Wireshark IDs of
 * our header fields; they are assigned values when we call
 * proto_register_field_array() in proto_register_uepi()
 */
static gint hf_uepi = -1;
static gint hf_uepi_session_id = -1;
static gint hf_uepi_psp_flags = -1;
static gint hf_uepi_psp_flags_vccv = -1;
static gint hf_uepi_psp_flags_seq = -1;
static gint hf_uepi_psp_ext_header = -1;
static gint hf_uepi_psp_flow_id = -1;
static gint hf_uepi_segment_count = -1;
static gint hf_uepi_sequence_number = -1;

static gint hf_uepi_segment_info = -1;

/* These are the ids of the subtrees */
static gint ett_uepi = -1;
static gint ett_uepi_psp_header = -1;
static gint ett_uepi_session_id = -1;
static gint ett_uepi_psp_flags = -1;
static gint ett_uepi_psp_flags_vccv = -1;
static gint ett_uepi_psp_flags_seq = -1;
static gint ett_uepi_psp_ext_header = -1;
static gint ett_uepi_psp_flow_id = -1;
static gint ett_uepi_segment_count = -1;
static gint ett_uepi_sequence_number = -1;

/** Table for subdissectors */
static dissector_table_t uepi_dissector_table = NULL;

#define L2TP_PROT       115     /* protocol number for L2TP */


/**
 * UEPI protocol handoff.
 */
void proto_reg_handoff_uepi( void )
{
    static gboolean initialized = FALSE;
    static dissector_handle_t uepi_handle = NULL;

    if ( !initialized )
    {
    	uepi_handle = create_dissector_handle( dissect_uepi, proto_uepi );
    	dissector_add_uint( "ip.proto", L2TP_PROT, uepi_handle );
        docsis_mgmt_handle  = find_dissector( "docsis_mgmt" );
        data_handle         = find_dissector( "data" );
    }
}

/**
 * Register the UEPI protocol dissector.
 * 
 */
void proto_register_uepi( void )
{
    /*
     * A header field is something you can search/filter on.
     * 
     * We create a structure to register our fields. It consists of an
     * array of hf_register_info structures, each of which are of the format
     * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
     */
    static hf_register_info hf[] = {
        { &hf_uepi,
            { "UEPI Protocol", "uepi.data", FT_NONE, BASE_NONE, NULL, 0x0,
                "UEPI Protocol", HFILL }},
        { &hf_uepi_session_id,
            { "L2TP Session ID   ", "uepi.sess_id", FT_UINT32, BASE_HEX, NULL, 0x0,
                "UEPI Session ID", HFILL }},
        { &hf_uepi_psp_flags,
            { "PSP SubLayer Flags", "uepi.psp_flags", FT_UINT8, BASE_HEX, NULL, 0x0,
                "PSP SubLayer Header Flags", HFILL }},
        { &hf_uepi_psp_flags_vccv,
            { "  VCCV", "uepi.psp_flags.vccv", FT_BOOLEAN, 8, NULL,
                UEPI_FLAG_VCCV, NULL, HFILL }},
        { &hf_uepi_psp_flags_seq,
            { "SeqVld", "uepi.psp_flags.seq", FT_BOOLEAN, 8, NULL,
                UEPI_FLAG_SEQ_VALID, "Sequence Number Valid", HFILL }},
        { &hf_uepi_psp_ext_header,
            { "ExtHdr", "uepi.ext_header", FT_UINT8, BASE_HEX_DEC, NULL,
                UEPI_FLAG_EXT_HEADER, "Extended Header", HFILL }},
        { &hf_uepi_psp_flow_id,
            { "FlowID", "uepi.flow_id", FT_UINT8, BASE_HEX_DEC, NULL,
                UEPI_FLAG_FLOW_ID, "PSP Flow ID", HFILL }},
        { &hf_uepi_segment_count,
            { "PSP Segment Count ", "uepi.seg_count", FT_UINT8, BASE_DEC, NULL, 0x0,
                "PSP Segment Count", HFILL }},
        { &hf_uepi_sequence_number,
            { "PSP Sequence No.  ", "uepi.seq_num", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                "PSP Sequence Number", HFILL }},
#if 1
        { &hf_uepi_segment_info,
            { "Segment information. ", "uepi.seg_info", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                "Segment information", HFILL }},
#endif
    };

    static gint *ett[] = {
        &ett_uepi,
        &ett_uepi_psp_header,
        &ett_uepi_session_id,
        &ett_uepi_psp_flags,
        &ett_uepi_psp_flags_vccv,
        &ett_uepi_psp_flags_seq,
        &ett_uepi_psp_ext_header,
        &ett_uepi_segment_count,
        &ett_uepi_sequence_number,
    };

    /* Execute protocol initialization only once */
    if ( proto_uepi == -1 )
    {
        proto_uepi = proto_register_protocol( "UEPI Protocol as used by Cisco Quetzal/3Gx60",
                                              "UEPI", "uepi" );
        proto_register_field_array( proto_uepi, hf, array_length( hf ));
        proto_register_subtree_array( ett, array_length( ett ));

        uepi_module = prefs_register_protocol( proto_uepi, NULL );
        prefs_register_bool_preference( uepi_module, "uepi",
                                        "UEPI REQUEST Frame",
                                        "Dissect UEPI Request Frames.",
                                        &uepi_dissect_flag );

        register_dissector( "uepi", dissect_uepi, proto_uepi );

        /* Create the UEPI subdissector table based on PW TYPE */
        uepi_dissector_table = register_dissector_table( "uepi.pw",
                                        "UEPI Encapsulation Type",
                                        FT_UINT8, BASE_HEX );
    }

    DEP( 1, ( "Registered UEPI dissector\r\n" ));
}

/**
 *  Main dissect routine for UEPI.
 */
static void dissect_uepi( tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree )
{
    char titleStr[ 132 ];
    char tmpStr[ 80 ];
    proto_item *uepi_item = NULL;
    proto_item *uepi_sub_item = NULL;
    proto_tree *uepi_tree = NULL;
    proto_tree *uepi_segment_tree = NULL;
    guint32 offset;
    guint8  idx, *pDevId;


    //if ( check_col( pinfo->cinfo, COL_PROTOCOL ))
        col_set_str( pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_UEPI );

    /* Clear out stuff in the info column */
    //if ( check_col( pinfo->cinfo, COL_INFO ))
        col_clear( pinfo->cinfo, COL_INFO );

    offset = 0;

    uepi_info.session_id = tvb_get_ntohl( tvb, offset );
    offset += 4;
    uepi_info.flags = tvb_get_guint8( tvb, offset );
    offset++;
    uepi_info.seg_count = tvb_get_guint8( tvb, offset );
    offset++;

    /* Sequence Number */
    uepi_info.seqNo = tvb_get_ntohs( tvb, offset );
    offset += 2;

    DEP( 3, ( "%s:%d frame %u, sess %X, flags %X, seg_count %u\r\n",
              __FUNCTION__, __LINE__, pinfo->fd->num, uepi_info.session_id,
              uepi_info.flags, uepi_info.seg_count ));

    pDevId = (guint8 *)( pinfo->dl_src.data );
    uepi_info.pwType = BCM3142_PW_TYPE_DECODE( uepi_info.session_id );
    switch( uepi_info.pwType )
    {
        case PW_SESSION_MAP:
            sprintf( titleStr, "[UEPI  MAP]" );
            pDevId = (guint8 *)( pinfo->dl_dst.data );  /* To Mg */
            break;
        case PW_SESSION_DATA:
            sprintf( titleStr, "[UEPI DATA]" );
            break;
        case PW_SESSION_REQUEST:
            sprintf( titleStr, "[UEPI  REQ]" );
            break;
        case PW_SESSION_RNG_REQ:
            sprintf( titleStr, "[UEPI  RNG]" );
            break;
        case PW_SESSION_SPEC_MGMT:
            sprintf( titleStr, "[UEPI  FFT]" );
            break;
        case PW_SESSION_DIAG:
            sprintf( titleStr, "[UEPI DIAG]" );
            pDevId = (guint8 *)( pinfo->dl_dst.data );  /* To Mg */
            break;

        default:
            sprintf( titleStr, "[UEPI UNKOWN]" );
        break;
    }  /* _switch PW */

    uepi_info.devId = *pDevId;

    sprintf( tmpStr, " Mg%u/Seq %05u: ", pDevId[ 5 ] >> 1,
             uepi_info.seqNo  );
    strcat( titleStr, tmpStr );

#if 0
    if ( check_col( pinfo->cinfo, COL_INFO ))
    {
        //col_add_fstr( pinfo->cinfo, COL_INFO, "%s", titleStr );
        //col_prepend_fence_fstr( pinfo->cinfo, COL_INFO, titleStr );
        col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s", snmp_PDUs_vals[pdu_type].strptr);
    }
#endif

    if ( tree )         /* we are being asked for details */
    {
        guint32 psp_length;        /* Broadcom header is fixed length of 12 bytes. */

        offset = 0;
        /* Create the top-level Register Process tree */
        uepi_item = proto_tree_add_item( tree, proto_uepi, tvb, 0, -1, FALSE );
        uepi_tree = proto_item_add_subtree( uepi_item, ett_uepi );

        proto_tree_add_uint( uepi_tree, hf_uepi_session_id,
                             tvb, offset, 4, uepi_info.session_id );
        offset += 4;

        /* Create a tree for the PSP Header. */
        uepi_tree = proto_item_add_subtree( uepi_item, ett_uepi );

        /* PSP Header is four bytes + variable segment info */
        psp_length = 4 + (uepi_info.seg_count * 2);

        /* Add the flags */
        proto_tree_add_item( uepi_tree, hf_uepi_psp_flags,
                             tvb, offset, 1, FALSE );
        proto_tree_add_item( uepi_tree, hf_uepi_psp_flags_vccv,
                             tvb, 4, 1, FALSE );
        proto_tree_add_item( uepi_tree, hf_uepi_psp_flags_seq,
                             tvb, 4, 1, FALSE );
        proto_tree_add_item( uepi_tree, hf_uepi_psp_ext_header,
                             tvb, 4, 1, FALSE );
        proto_tree_add_item( uepi_tree, hf_uepi_psp_flow_id,
                             tvb, 4, 1, FALSE );
        offset++;

        /* PSP Segment Count */
        proto_tree_add_uint( uepi_tree, hf_uepi_segment_count,
                             tvb, offset, 1, uepi_info.seg_count );
        offset++;

        /* PSP Sequence Number */
        proto_tree_add_uint( uepi_tree, hf_uepi_sequence_number,
                             tvb, offset, 2, uepi_info.seqNo );
        offset += 2;

        for ( idx = 0; idx < uepi_info.seg_count; idx++ )
        {
            uepi_info.segInfo[ idx ] = tvb_get_ntohs( tvb, offset );

            proto_tree_add_uint( uepi_tree, hf_uepi_segment_info,
                             tvb, offset, 2, tvb_get_ntohs( tvb, offset ));
            #/*
            proto_tree_add_uint( uepi_tree, tvb, offset, 2,
                                 "Segment %u: BEGIN:%u END:%u, %08X [%u] bytes",
                                 idx + 1, (uepi_info.segInfo[ idx ] & PSP_FLAG_BEGIN) ? 1 : 0,
                                 (uepi_info.segInfo[ idx ] & PSP_FLAG_END) ? 1 : 0,
                                 uepi_info.segInfo[ idx ] & PSP_SEG_LENGTH,
                                 uepi_info.segInfo[ idx ] & PSP_SEG_LENGTH );
                                 */
            offset += 2;
        }

        /*
         * Dissect the Segments ...
         */
        dissect_uepi_segment( tvb, pinfo, uepi_tree, offset );
    }  /* _if tree */

    //if ( check_col( pinfo->cinfo, COL_INFO ))
        col_prepend_fence_fstr( pinfo->cinfo, COL_INFO, titleStr );
}

/**
 * Decode the PSP Segment(s).
 * 
 * @param tvb 
 * @param pinfo 
 * @param tree 
 * @param offset 
 */
void dissect_uepi_segment( tvbuff_t *tvb, packet_info *pinfo,
                           proto_tree *tree, gint offset )
{
    tvbuff_t *next_tvb;

    /* Make the next tvbuff ... */
    next_tvb = tvb_new_subset( tvb, offset, -1, -1 );

    /* Pass the UEPI header information to subdissectors ... */
    pinfo->private_data = &uepi_info;

    /* Call the dissector based on its PW Type 
    if ( dissector_try_port( uepi_dissector_table, uepi_info.pwType,
                             next_tvb, pinfo, tree ))
    {    
        DEP( 1, ( "%s: Pkt %u found dissector for PwType %X\n",
                  __FUNCTION__, pinfo->fd->num, uepi_info.pwType ));
        //col_prepend_fence_fstr( pinfo->cinfo, COL_INFO, "UEPI: " );
        return;
    }
    */
    /* call the next dissector */
    switch( uepi_info.pwType )
    {
        case PW_SESSION_MAP:
            if ( NULL != docsis_mgmt_handle )
                call_dissector( docsis_mgmt_handle, next_tvb, pinfo, tree );
            break;

        case PW_SESSION_SPEC_MGMT:
        case PW_SESSION_DIAG:
            if ( NULL != data_handle )
                call_dissector( data_handle, next_tvb, pinfo, tree );
            break;

        default:
            if ( NULL != data_handle )
                call_dissector( data_handle, next_tvb, pinfo, tree );
            break;
    }  /* _switch pwType */
}

/***************************************************************************/

/**
 * Convert the given mask to a string of bits.
 * 
 * @param bits 
 * @param mask 
 * 
 * @return char* 
 */
static char *bitmaskToString( guint8 bits, guint32 mask )
{
    static char outStr[ 32 + 8 ];
    gint32 idx, pos;

    pos = 0;
    bits--;
    for ( idx = bits; idx >= 0; idx-- )
    {
        if ( mask & (1 << idx ))
            outStr[ pos ] = '1';
        else
            outStr[ pos ] = '0';
        pos++;
        if (( idx != 0 ) && (( idx % 4 ) == 0 ))
        {
            outStr[ pos ] = '.';
            pos++;
        }
    }

    return( outStr );
}

