<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: BSD-2-Clause
-->

# TPM2 Proxy Broker

This is a Linux system service that implements a TPM Command Transmission
Interface ([TCTI][]) proxy.
It inspects TPM commands from downstream clients, checks them against a
configurable access and permission list, and conditionally sends them
to an upstream TCTI.

The primary use for this service is to allow fine-grained per-user access
to a physical TPM, similar to how Windows's [TBS][] works.

Note: This service is not a [TPM Access Broker][TAB]!
To allow downstream clients to access the physical TPM, you must enable the
Linux kernel resource manager (`/dev/tpmrm0`, recommended) or use the
userland implementation [tpm2-abrmd][].

[TCTI]: https://trustedcomputinggroup.org/resource/tss-tcti-specification/
[TBS]: https://learn.microsoft.com/en-us/windows/win32/tbs/tpm-base-services-portal
[TAB]: https://trustedcomputinggroup.org/resource/tss-tab-and-resource-manager/
[tpm2-abrmd]: https://github.com/tpm2-software/tpm2-abrmd
