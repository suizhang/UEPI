/**
 * @file
 * BCM3142/UEPI REQUEST Dissector.
 */


#include "config.h"


#include <stdio.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <epan/packet.h>
#include <string.h>
#include "uepi.h"

static int proto_uepi_request = -1;
static gint debug_level = 2;

static gint hf_uepi_req = -1, ett_uepi_req = -1;
static gint hf_status_vers = -1;
static gint hf_status_sid_cluster = -1;
static gint hf_status_sid_cluster_valid = -1;
static gint hf_status_req_units = -1;
static gint hf_status_req_type = -1;
static gint hf_iuc = -1;
static gint hf_reqsize = -1;
static gint hf_sched_sid = -1;
static gint hf_lc_sess = -1;
static gint hf_start_ms = -1;
static gint hf_embed_sid = -1;


/** Private info passed to subdissectors -- contains the UEPI header. */
static uepi_info_t *pUepi_info = NULL;

static void dissect_uepi_request( tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree );

static const value_string reqTypes[] = {
    { 0, "Stand Alone Request Frame" },
    { 1, "Piggyback Request" },
    { 0, NULL }
};

static const value_string reqUnits[] = {
    { 0, "Request is in minislots" },
    { 1, "Request is in N bytes" },
    { 0, NULL }
};

/** IUC Types */
static const value_string iucStrs[] = {
    { 1,  "Request" },
    { 2,  "Request Data" },
    { 3,  "Initial Maintenance" },
    { 4,  "Station Maintenance" },
    { 5,  "Short Data Grant" },
    { 6,  "Long Data Grant" },
    { 7,  "Reserved" },
    { 8,  "Reserved" },
    { 9,  "A/TDMA Short Data Grant" },
    { 10, "A/TDMA Long Data Grant" },
    { 11, "A/TDMA Unsolicited Grant Service" },
    { 0, NULL }
};

#if 1
    #define DEP( level, msg ) if ( level <= debug_level ) { g_printf msg; }
    /* Could also use: proto_tree_add_debug_text(tree, format) */
#else
    #define DEP( level, msg )
//proto_tree_add_debug_text(tree, format)
#endif

/**
 * Register the UEPI protocol dissector.
 * UEPI protocol handoff.
 * 
 */
void proto_register_uepi_request( void )
{
    dissector_handle_t uepi_request_handle;
    static gboolean initialized = FALSE;
    static dissector_handle_t uepi_handle = NULL;
    static gint *ett[] = {
        &ett_uepi_req,
    };

    #define REQ_FLAG_VERS           0xC0
    #define REQ_FLAG_SID_CL         0x38
    #define REQ_FLAG_SID_CL_VALID   0x04
    #define REQ_FLAG_UNITS          0x02
    #define REQ_FLAG_TYPE           0x01

    static hf_register_info hf[] = {
        { &hf_uepi_req,
            { "Request", "uepi.req", FT_NONE, BASE_NONE, NULL, 0x0,
                "UEPI Request", HFILL }},
        { &hf_status_vers,
            { " Version Number", "uepi.req.vers", FT_UINT8, BASE_HEX, NULL,
                REQ_FLAG_VERS, NULL, HFILL }},
        { &hf_status_sid_cluster,
            { "    SID Cluster", "uepi.req.cluster", FT_UINT8, BASE_HEX, NULL,
                REQ_FLAG_SID_CL, NULL, HFILL }},
        { &hf_status_sid_cluster_valid,
            { "SID Clstr Valid", "uepi.req.seq", FT_BOOLEAN, 8, NULL,
                REQ_FLAG_SID_CL_VALID, NULL, HFILL }},
        { &hf_status_req_units,
            { "  REQUEST Units", "uepi.req.units", FT_UINT8, BASE_HEX_DEC, reqUnits,
                REQ_FLAG_UNITS, NULL, HFILL }},
        { &hf_status_req_type,
            { "   REQUEST Type", "uepi.req.type", FT_UINT8, BASE_HEX_DEC, reqTypes,
                REQ_FLAG_TYPE, "Minislots or bytes", HFILL }},
        { &hf_iuc,
            { "Request  IUC  ", "uepi.req.iuc", FT_BYTES, BASE_NONE, NULL, 0x0,
                "Request Interval Usage Code", HFILL }},
        { &hf_reqsize,
            { "Request  Size ", "uepi.req.reqsize", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                "Request Size in bytes or minislots", HFILL }},
        { &hf_sched_sid,
            { "Scheduled  SID", "uepi.req.sched_sid", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                "SID used in MAP to grant BW for the TX opp in which REQ was received.", HFILL }},
        { &hf_embed_sid,
            { "Embedded  SID ", "uepi.req.embed_sid", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                "SID from REQ Frame, Queue-depth or Piggyback Request in DOCSIS Ext Header", HFILL }},
        { &hf_start_ms,
            { "Start Minislot", "uepi.req.start_ms", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
                "Minislot num corresponding to the start of the transmit opportunity", HFILL }},
        { &hf_lc_sess,
            { "LC Session ID ", "uepi.req.lc_sess", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
                "L2TP SessID of the UEPI Data PW assoc w/ LogChan Req was rcvd.", HFILL }},
    };

    /* Register the protocol name and description */
    proto_uepi_request = proto_register_protocol( "UEPI Request", "UEPI REQUEST",
                                                  "uepi_request" );

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array( proto_uepi_request, hf, array_length( hf ));
    proto_register_subtree_array( ett, array_length( ett ));

    uepi_request_handle = create_dissector_handle( dissect_uepi_request, proto_uepi_request );
    dissector_add_uint( "uepi.pw", PW_SESSION_REQUEST, uepi_request_handle );
}

/**
 * Dissect the Single-Segment REQUEST
 * 
 * @param tvb 
 * @param pinfo 
 * @param tree 
 * @param offset 
 */
static void dissect_uepi_request( tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree )
{
    guint32 offset, startMs;
    guint8  iuc;
    guint16 reqSize, schedSid, embedSid;
    proto_item *req_item = NULL;
    proto_tree *req_tree = NULL;


    /* Get the data with the UEPI header information. */
    pUepi_info = (uepi_info_t *) pinfo->private_data;

    if ( tree )         /* we are being asked for details */
    {
        guint8  status;

        /* Create the top-level Register Process tree */
        req_item = proto_tree_add_item( tree->parent, proto_uepi_request, tvb, 0, -1, FALSE );
        req_tree = proto_item_add_subtree( req_item, ett_uepi_req );

        /* Add the flags */
        offset = 0;
        status = tvb_get_guint8( tvb, offset );
        proto_tree_add_item( req_tree, hf_status_vers, tvb, offset, 1, FALSE );
        proto_tree_add_item( req_tree, hf_status_sid_cluster, tvb, offset, 1, FALSE );
        proto_tree_add_item( req_tree, hf_status_sid_cluster_valid, tvb, offset, 1, FALSE );
        proto_tree_add_item( req_tree, hf_status_req_units, tvb, offset, 1, FALSE );
        proto_tree_add_item( req_tree, hf_status_req_type, tvb, offset, 1, FALSE );
        offset++;

        //if ( check_col( pinfo->cinfo, COL_INFO ))
        {    
            col_append_str( pinfo->cinfo, COL_INFO,
                            val_to_str(( status & REQ_FLAG_TYPE ),
                                       reqTypes, "Unknown Type" ));
        }

        /* IUC */
        iuc = tvb_get_guint8( tvb, offset );
        proto_tree_add_bytes_format( req_tree, hf_iuc, tvb, offset, 1,
                             tvb_get_ptr( tvb, offset, 1 ),
                             "REQUEST  IUC  : %u - %s", iuc,
                             val_to_str( iuc, iucStrs, "Unknown IUC" ));
        offset++;

        /* REQ Size -- number of mini slots or bytes requested */
        reqSize = tvb_get_ntohs( tvb, offset );
        proto_tree_add_uint( req_tree, hf_reqsize, tvb, offset, 2, reqSize );
        offset += 2;

        /* Scheduled SID */
        schedSid = tvb_get_ntohs( tvb, offset );
        proto_tree_add_uint( req_tree, hf_sched_sid, tvb, offset, 2, schedSid );
        offset += 2;

        /* Embedded SID */
        embedSid = tvb_get_ntohs( tvb, offset );
        proto_tree_add_uint( req_tree, hf_embed_sid, tvb, offset, 2, embedSid );
        offset += 2;

        /* Start Minislot */
        startMs = tvb_get_ntohl( tvb, offset );
        proto_tree_add_uint( req_tree, hf_start_ms, tvb, offset, 4, startMs );
        offset += 4;

        /* L2TP Session */
        proto_tree_add_uint( req_tree, hf_lc_sess, tvb,
                             offset, 4, tvb_get_ntohl( tvb, offset ));
        offset += 4;

        //if ( check_col( pinfo->cinfo, COL_INFO ))
        {    
            col_append_fstr( pinfo->cinfo, COL_INFO, ", Sch.SID = %u, Emb.SID = %u",
                            schedSid, embedSid );
        }
    }  /* _if tree */
}

