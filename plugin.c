/*
 * Do not modify this file. Changes will be overwritten.
 *
 * Generated automatically from ../../tools/make-dissector-reg.py.
 */

#include "config.h"

#include <gmodule.h>

#include "moduleinfo.h"

/* plugins are DLLs */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

#ifndef ENABLE_STATIC
WS_DLL_PUBLIC_DEF void plugin_register (void);
WS_DLL_PUBLIC_DEF const gchar version[] = VERSION;

/* Start the functions we need for the plugin stuff */

WS_DLL_PUBLIC_DEF void
plugin_register (void)
{
    {extern void proto_register_uepi (void); proto_register_uepi ();}
    {extern void proto_register_uepi_data (void); proto_register_uepi_data ();}
    {extern void proto_register_uepi_ranging (void); proto_register_uepi_ranging ();}
    {extern void proto_register_uepi_request (void); proto_register_uepi_request ();}
}

WS_DLL_PUBLIC_DEF void plugin_reg_handoff(void);

WS_DLL_PUBLIC_DEF void
plugin_reg_handoff(void)
{
    {extern void proto_reg_handoff_uepi (void); proto_reg_handoff_uepi ();}
}
#endif
