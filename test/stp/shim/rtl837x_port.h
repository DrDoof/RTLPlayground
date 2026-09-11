/* Host-build shim: the harness mocks trunk programming and records calls */
#ifndef _SHIM_RTL837X_PORT_H_
#define _SHIM_RTL837X_PORT_H_
#include <stdint.h>
void port_lag_members_set(uint8_t lag, uint16_t members);
void port_isolate(uint8_t port, uint16_t pmask);
uint16_t port_pvid_get(uint8_t port);
#endif

typedef uint8_t vlan_ingress_mode_t;
int8_t vlan_get(uint16_t vlan);
uint16_t port_pvid_get(uint8_t port);
void port_l2mc_set(uint8_t mac_last, uint16_t vid, uint16_t pmask);
void port_l2_forget_port(uint8_t port);
vlan_ingress_mode_t port_ingress_filter_get(uint8_t port);
#define VLAN_TAGGED 1
