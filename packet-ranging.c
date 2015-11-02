/**
 * @file
 * UEPI Ranging frame dissector.
 *
 * Handles BCM3142/UEPI Ranging packets.
 */


#include "config.h"

#include <stdio.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <epan/packet.h>
#include <string.h>
#include "uepi.h"

static dissector_handle_t docsis_handle = NULL;
static int proto_uepi_ranging = -1;
static gint debug_level = 2;

/* Header fields ... */
static gint hf_uepi_rng_header = -1, ett_uepi_rng_header = -1;
static gint hf_uepi_rng_data = -1, ett_uepi_rng_data = -1;
static gint hf_uepi_rng_trailer = -1, ett_uepi_rng_trailer = -1;
static gint hf_status_vers = -1;
static gint hf_status_payload = -1;
static gint hf_iuc = -1;
static gint hf_sched_sid = -1;
static gint hf_start_ms = -1;

static gint ett_status_vers = -1, ett_status_payload =-1;
static gint ett_iuc = -1, ett_sched_sid = -1, ett_start_ms = -1;

/* Trailer fields ... */
static gint hf_t_status_vers = -1, hf_t_status_rng_reqd = -1, hf_t_status_lt_snr_low = -1;
static gint hf_t_status_int_phy_err = -1, hf_t_status_hi_energy = -1;
static gint hf_t_status_lo_energy = -1, hf_t_status_fec_valid = -1;
static gint hf_t_status_snr_valid = -1, hf_t_status_eq_present = -1;
static gint hf_t_status_vend_pres = -1, hf_t_good_fec = -1;
static gint hf_t_corr_fec = -1, hf_t_uncorr_fec = -1;
static gint hf_t_snr =-1;
static gint hf_t_power = -1, hf_t_freqerr = -1;
static gint hf_t_timerr = -1, hf_t_eq_coeff = -1;
static gint hf_t_vend_id = -1, hf_t_vend_len = -1, hf_t_vend_bytes = -1;

static gint ett_t_status_vers = -1, ett_t_status_rng_reqd = -1, ett_t_status_lt_snr_low = -1;
static gint ett_t_status_int_phy_err = -1, ett_t_status_hi_energy = -1;
static gint ett_t_status_lo_energy = -1, ett_t_status_fec_valid = -1;
static gint ett_t_status_snr_valid = -1, ett_t_status_eq_present = -1;
static gint ett_t_status_vend_pres = -1, ett_t_good_fec = -1;
static gint ett_t_corr_fec = -1, ett_t_uncorr_fec = -1;
static gint ett_t_snr =-1;

/** Private info passed to subdissectors -- contains the UEPI header. */
static uepi_info_t *pUepi_info = NULL;

static void dissect_uepi_ranging( tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree );

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
 * Register the UEPI protocol dissector for RANGING.
 * UEPI protocol handoff.
 */
void proto_register_uepi_ranging( void )
{
    dissector_handle_t uepi_ranging_handle = NULL;
    static gint *ett_ranging[] = {
        &ett_uepi_rng_header,
        &ett_status_vers, &ett_status_payload, &ett_iuc, &ett_sched_sid, &ett_start_ms,
        &ett_uepi_rng_data,
        &ett_uepi_rng_trailer,
        &ett_t_status_vers, &ett_t_status_rng_reqd, &ett_t_status_lt_snr_low,
        &ett_t_status_int_phy_err, &ett_t_status_hi_energy,
        &ett_t_status_lo_energy, &ett_t_status_fec_valid,
        &ett_t_status_snr_valid, &ett_t_status_eq_present,
        &ett_t_status_vend_pres, &ett_t_good_fec,
        &ett_t_corr_fec, &ett_t_uncorr_fec,
        &ett_t_snr,
    };

    #define HDR_FLAG_VERS            0xC0
    #define HDR_FLAG_NO_PAYLOAD      0x20
    #define TRL_FLAG_VERS            (0x3 << 14)
    #define TRL_FLAG_RNG_REQD        (1 << 12)
    #define TRL_FLAG_LT_SNR_LOW      (1 << 11)
    #define TRL_FLAG_INT_PHY_ERR     (1 << 10)
    #define TRL_FLAG_HI_ENERGY       (1 << 9)
    #define TRL_FLAG_LO_ENERGY       (1 << 8)
    #define TRL_FLAG_FEC_VLD         (1 << 3)
    #define TRL_FLAG_SNR_VLD         (1 << 2)
    #define TRL_FLAG_EQ_PRESENT      (1 << 1)
    #define TRL_FLAG_VENDOR_PRESENT  (1 << 0)

    static hf_register_info hf_ranging[] = {
        /* ** HEADER ** */
        { &hf_uepi_rng_header,
            { "UEPI Ranging - PSP Header Segment", "uepi.hdr", FT_NONE, BASE_NONE,
                NULL, 0x0, "UEPI Ranging PSP Header Segment", HFILL }},
        { &hf_status_vers,
            { " Version Number", "uepi.ranging.vers", FT_UINT8, BASE_HEX_DEC, NULL,
                HDR_FLAG_VERS, "Header Version Number", HFILL }},
        { &hf_status_payload,
            { "Payload!Present", "uepi.ranging.payload", FT_BOOLEAN, 8, NULL,
                HDR_FLAG_NO_PAYLOAD, "No Burst Event", HFILL }},
        { &hf_iuc,
            { "Request  IUC  ", "uepi.ranging.iuc", FT_BYTES, BASE_NONE, NULL, 0x0,
                "Request Interval Usage Code ranging was received on.", HFILL }},
        { &hf_sched_sid,
            { "Scheduled  SID", "uepi.ranging.sched_sid", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                "SID used in MAP to grant BW for the TX opp in which RNG was received.", HFILL }},
        { &hf_start_ms,
            { "Start Minislot", "uepi.ranging.start_ms", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
                "Minislot num corresponding to the start of the transmit opportunity", HFILL }},

        /* ** DATA ** */
        { &hf_uepi_rng_data,
            { "UEPI Ranging - PSP Data Segment", "uepi.hdr", FT_NONE, BASE_NONE,
                NULL, 0x0, "UEPI Ranging PSP Data Segment", HFILL }},
        
        /* ** TRAILER ** */
        { &hf_uepi_rng_trailer,
            { "UEPI Ranging - PSP Trailer Segment", "uepi.tr", FT_NONE, BASE_NONE,
                NULL, 0x0, "UEPI Ranging PSP Trailer Segment", HFILL }},
        { &hf_t_status_vers,
            { "Version  No.", "uepi.ranging.vers", FT_UINT16, BASE_HEX_DEC, NULL,
                TRL_FLAG_VERS, "Trailer Version Number", HFILL }},
        { &hf_t_status_rng_reqd,
            { "Rng Required", "uepi.ranging.rngreqd", FT_BOOLEAN, 16, NULL,
                TRL_FLAG_RNG_REQD, "Ranging Required", HFILL }},
        { &hf_t_status_lt_snr_low,
            { "LngT SNR Low", "uepi.ranging.lt_snr", FT_BOOLEAN, 16, NULL,
                TRL_FLAG_LT_SNR_LOW, "Long Term SNR below threshold", HFILL }},
        { &hf_t_status_int_phy_err,
            { "Int. PHY Err", "uepi.ranging.payload", FT_BOOLEAN, 16, NULL,
                TRL_FLAG_INT_PHY_ERR, "Internal PHY error detected", HFILL }},
        { &hf_t_status_hi_energy,
            { "High  Energy", "uepi.ranging.hi_energy", FT_BOOLEAN, 16, NULL,
                TRL_FLAG_HI_ENERGY, "Burst power above high-energy threshold", HFILL }},
        { &hf_t_status_lo_energy,
            { "Low  Energy ", "uepi.ranging.low_energy", FT_BOOLEAN, 16, NULL,
                TRL_FLAG_LO_ENERGY, "Burst power below low-energy threshold", HFILL }},
        { &hf_t_status_fec_valid,
            { "FEC  Valid  ", "uepi.ranging.fec", FT_BOOLEAN, 16, NULL,
                TRL_FLAG_FEC_VLD, "Good/Correct/Uncorrect FEC counters valid", HFILL }},
        { &hf_t_status_snr_valid,
            { "SNR  Valid  ", "uepi.ranging.snr", FT_BOOLEAN, 16, NULL,
                TRL_FLAG_SNR_VLD, "Burst payload SNR field is valid", HFILL }},
        { &hf_t_status_eq_present,
            { "RnqEQ Presnt", "uepi.ranging.eq", FT_BOOLEAN, 16, NULL,
                TRL_FLAG_EQ_PRESENT, "Burst power/Freq Error/Coefficients are present", HFILL }},
        { &hf_t_status_vend_pres,
            { "Vendor Field", "uepi.ranging.vendor", FT_BOOLEAN, 16, NULL,
                TRL_FLAG_VENDOR_PRESENT, "Vendor-specific field present", HFILL }},
        { &hf_t_good_fec,
            { "Good  FEC      ", "uepi.ranging.goodfec", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                "Number of good FEC blocks received in the burst.", HFILL }},
        { &hf_t_corr_fec,
            { "Corrected FEC  ", "uepi.ranging.corrfec", FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
                "Number of FEC blocks received in the burst which had errors that were corrected", HFILL }},
        { &hf_t_uncorr_fec,
            { "Uncorrected FEC", "uepi.ranging.uncorrfec", FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
                "Number of uncorrectable FEC blocks received in the burst", HFILL }},
        { &hf_t_snr,
            { "Burst Payld SNR", "uepi.ranging.snr", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                "Burst payload SNR, reported as average slicer error over the payload of the burst", HFILL }},
        { &hf_t_power,
            { "Burst Power    ", "uepi.ranging.power", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                "Measured burst power", HFILL }},
        { &hf_t_freqerr,
            { "Frequenct Error", "uepi.ranging.freqerr", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                "Frequency Error", HFILL }},
        { &hf_t_timerr,
            { "Timing Error   ", "uepi.ranging.timerr", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
                "Measured timing error", HFILL }},
        { &hf_t_eq_coeff,
            { "Equalizer Coeff", "uepi.ranging.coeff", FT_BYTES, BASE_NONE, NULL, 0x0,
                "Complex coefficients for pre-equalization as determined by PHY based on this burst", HFILL }},
        { &hf_t_vend_id,
            { "Vendor ID", "uepi.ranging.vend_id", FT_BYTES, BASE_NONE, NULL, 0x0,
                "IANA-assigned Vendor ID", HFILL }},
        { &hf_t_vend_len,
            { "Vendor Length", "uepi.ranging.vend_len", FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
                "Vendor specific field length", HFILL }},
        { &hf_t_vend_bytes,
            { "Vendor-specific contents", "uepi.ranging.vend_bytes", FT_BYTES, BASE_NONE, NULL, 0x0,
                "Vendor-specific contents", HFILL }},
    };

    /* Register the protocol name and description */
    proto_uepi_ranging = proto_register_protocol( "UEPI Ranging PSP Payload",
                                                  "UEPI RANGING", "uepi_ranging" );

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array( proto_uepi_ranging, hf_ranging, array_length( hf_ranging ));
    proto_register_subtree_array( ett_ranging, array_length( ett_ranging ));

    uepi_ranging_handle = create_dissector_handle( dissect_uepi_ranging, proto_uepi_ranging );
    dissector_add_uint( "uepi.pw", PW_SESSION_RNG_REQ, uepi_ranging_handle );

    docsis_handle  = find_dissector( "docsis" );
}

/**
 * Dissect the Single-Segment REQUEST
 * 
 * @param tvb 
 * @param pinfo 
 * @param tree 
 * @param offset 
 */
static void dissect_uepi_ranging( tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree )
{
    guint32 offset, startMs;
    guint8  iuc, segment;
    guint16 schedSid;
    proto_item *rng_hdr_item = NULL, *rng_trl_item = NULL, *rng_data_item = NULL;
    proto_tree *rng_hdr_tree = NULL, *rng_trl_tree = NULL, *rng_data_tree = NULL;


    /* Get the private data with the UEPI header information. */
    pUepi_info = (uepi_info_t *) pinfo->private_data;

    if ( tree )         /* we are being asked for details */
    {
        gint8  header_status;
        gint16 trailer_status;

        /* Top level Payload container/tag selecting ALL segments ... */
        offset = 0;
        segment = 0;

        /*
         ** HEADER SEGMENT
         ** Create the top-level Ranging trees -- add to UEPI header's parent.
         */
        rng_hdr_item = proto_tree_add_item( tree->parent, hf_uepi_rng_header,
                                            tvb, offset,
                                            pUepi_info->segInfo[ segment ] & PSP_SEG_LENGTH,
                                            FALSE );
        rng_hdr_tree = proto_item_add_subtree( rng_hdr_item, ett_uepi_rng_header );

        /* Add the HEADER flags */
        header_status = tvb_get_guint8( tvb, offset );
        proto_tree_add_item( rng_hdr_tree, hf_status_vers, tvb, offset, 1, FALSE );
        proto_tree_add_item( rng_hdr_tree, hf_status_payload, tvb, offset, 1, FALSE );
        offset++;

        /* IUC */
        iuc = tvb_get_guint8( tvb, offset );
        proto_tree_add_bytes_format( rng_hdr_tree, hf_iuc, tvb, offset, 1,
                             tvb_get_ptr( tvb, offset, 1 ),
                             "REQUEST  IUC  : %u - %s", iuc,
                             val_to_str( iuc, iucStrs, "Unknown IUC" ));
        offset++;

        /* Scheduled SID */
        schedSid = tvb_get_ntohs( tvb, offset );
        proto_tree_add_uint( rng_hdr_tree, hf_sched_sid, tvb, offset, 2, schedSid );
        offset += 2;

        /* Start Minislot */
        startMs = tvb_get_ntohl( tvb, offset );
        proto_tree_add_uint( rng_hdr_tree, hf_start_ms, tvb, offset, 4, startMs );
        offset += 4;
        segment++;

        /*
         ** DATA SEGMENT -- Not present for NO BURST Event TRUE
         */
        if (( header_status & HDR_FLAG_NO_PAYLOAD ) == 0)
        {
            rng_data_item = proto_tree_add_item( tree->parent, hf_uepi_rng_data,
                                                 tvb, offset,
                                                 pUepi_info->segInfo[ segment ] & PSP_SEG_LENGTH,
                                                 FALSE );
            rng_data_tree = proto_item_add_subtree( rng_data_item, ett_uepi_rng_data );
            if ( NULL != docsis_handle )
            {    
                tvbuff_t *data_tvb;
                gint len = pUepi_info->segInfo[ segment ] & PSP_SEG_LENGTH;
    
                /* Make the data segment's tvbuff ... */
                data_tvb = tvb_new_subset( tvb, offset, len, len );
                call_dissector( docsis_handle, data_tvb, pinfo, rng_data_tree );
            }
    
            offset += pUepi_info->segInfo[ segment ] & PSP_SEG_LENGTH;
            segment++;
        }

        /*
         ** Trailer SEGMENT
         */
        rng_trl_item = proto_tree_add_item( tree->parent, hf_uepi_rng_trailer,
                                            tvb, offset,
                                            pUepi_info->segInfo[ segment ] & PSP_SEG_LENGTH,
                                            FALSE );
        rng_trl_tree = proto_item_add_subtree( rng_trl_item, ett_uepi_rng_trailer );

        /* Trailer Status / Flags */
        trailer_status = tvb_get_ntohs( tvb, offset );
        proto_tree_add_item( rng_trl_tree, hf_t_status_vers, tvb, offset, 2, FALSE );
        proto_tree_add_item( rng_trl_tree, hf_t_status_rng_reqd, tvb, offset, 2, FALSE );
        proto_tree_add_item( rng_trl_tree, hf_t_status_lt_snr_low, tvb, offset, 2, FALSE );
        proto_tree_add_item( rng_trl_tree, hf_t_status_int_phy_err, tvb, offset, 2, FALSE );
        proto_tree_add_item( rng_trl_tree, hf_t_status_hi_energy, tvb, offset, 2, FALSE );
        proto_tree_add_item( rng_trl_tree, hf_t_status_lo_energy, tvb, offset, 2, FALSE );
        proto_tree_add_item( rng_trl_tree, hf_t_status_fec_valid, tvb, offset, 2, FALSE );
        proto_tree_add_item( rng_trl_tree, hf_t_status_snr_valid, tvb, offset, 2, FALSE );
        proto_tree_add_item( rng_trl_tree, hf_t_status_eq_present, tvb, offset, 2, FALSE );
        proto_tree_add_item( rng_trl_tree, hf_t_status_vend_pres, tvb, offset, 2, FALSE );
        offset += 2;

        /* Following fields are always present, but only valid for RngEQ Present */
        if ( trailer_status & TRL_FLAG_FEC_VLD )
        {
            proto_tree_add_item( rng_trl_tree, hf_t_good_fec, tvb, offset, 2, FALSE );
            offset += 2;
            proto_tree_add_item( rng_trl_tree, hf_t_corr_fec, tvb, offset, 1, FALSE );
            offset += 1;
            proto_tree_add_item( rng_trl_tree, hf_t_uncorr_fec, tvb, offset, 1, FALSE );
            offset += 1;
        }
        else
        {
            offset += 4;
        }

        /* Show SNR if Valid */
        if ( trailer_status & TRL_FLAG_SNR_VLD )
            proto_tree_add_item( rng_trl_tree, hf_t_snr, tvb, offset, 2, FALSE );
        offset += 2;

        /* Following fields are always present, but only valid for RngEQ TRUE */
        if ( trailer_status & TRL_FLAG_EQ_PRESENT )
        {
            proto_tree_add_item( rng_trl_tree, hf_t_power, tvb, offset, 2, FALSE );
            offset += 2;
            proto_tree_add_item( rng_trl_tree, hf_t_freqerr, tvb, offset, 2, FALSE );
            offset += 2;
            proto_tree_add_item( rng_trl_tree, hf_t_timerr, tvb, offset, 4, FALSE );
            offset += 4;
            proto_tree_add_item( rng_trl_tree, hf_t_eq_coeff, tvb, offset, 96, FALSE );
            offset += 96;
        }
        else
        {
            offset += 96 + 8;
        }

        if ( trailer_status & TRL_FLAG_VENDOR_PRESENT )
        {
            proto_tree_add_item( rng_trl_tree, hf_t_vend_id, tvb, offset, 3, FALSE );
            offset += 3;
            proto_tree_add_item( rng_trl_tree, hf_t_vend_len, tvb, offset, 1, FALSE );
            offset += 1;
            proto_tree_add_item( rng_trl_tree, hf_t_vend_bytes, tvb, offset, -1, FALSE );
        }
    }  /* _if tree */
}

