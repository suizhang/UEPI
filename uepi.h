/**
 *
 * @file
 * UEPI Header definition file.
 *
 * Defines UEPI specific flags, ranges, etc.
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef CMTS_UEPI_H
#define CMTS_UEPI_H

typedef struct uepi_info_s {
    guint8  seg_count;
    guint8  flags;
    guint16 seqNo;
    guint16 segInfo[ 256 ];
    guint32 session_id;
    guint32 offset;
    guint8  pwType;
    guint8  devId;
} uepi_info_t;

/**
 * PW Session "type" encoded into static session IDs.
 * For the ingress side of Mg only bits 9:0 are valid so MAPs are
 * kept @ session type 0.  Other types use a unique bit for easy identification.
 */
typedef enum pwSession_e {
    PW_SESSION_MAP       = 0x00,       /* Maps, per log chan, from LCP */
    PW_SESSION_DATA      = 0x01,       /* Burst data, per log chan */
    PW_SESSION_REQUEST   = 0x02,       /* Request */
    PW_SESSION_RNG_REQ   = 0x04,       /* Ranging Requests */
    PW_SESSION_SPEC_MGMT = 0x08,       /* Spectrum Management (IMP & FFT) */
    PW_SESSION_DIAG      = 0x10,       /* Diagnostic data path loopback */
} pwSessionT;

#define BCM3142_PW_TYPE_DECODE( sessId )    (( sessId >> 8 ) & 0xFF)

/** Flags for the PSP Header. */
#define UEPI_FLAG_VCCV	            0x80
#define UEPI_FLAG_SEQ_VALID	    0x40
#define UEPI_FLAG_EXT_HEADER	    0x30
#define UEPI_FLAG_FLOW_ID   	    0x0E

/** PSP Sublayer Segment Information */
#define PSP_FLAG_BEGIN              0x8000
#define PSP_FLAG_END                0x4000
#define PSP_SEG_LENGTH              0x3FFF


#endif /* CMTS_UEPI_H */

