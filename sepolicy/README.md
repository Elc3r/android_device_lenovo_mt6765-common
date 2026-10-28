# SELinux policy

Targets the pinned Android 12L/API32 platform and matching vendor blobs.
Android cold-boots Enforcing on the tested TB-X606X; standard userdebug `su`
and `backuptool` exceptions remain. Recovery is separately permissive.

Vendor policy is in `vendor/`; platform-side ECM/VT/audit contracts are in
`system_ext/public` and `system_ext/private`. Neverallow and Treble checks
remain enabled. No generic init-device or blanket app-property access is added.

## Contracts

- Hardware Keymaster, gatekeeper, TEE and FBE must remain compatible.
- `boot_property_defaults.te` enables vendor_init publication of finite vendor
  configuration groups. Platform defaults belong in system.prop. The generated
  USB fallback is removed from vendor build.prop by the product blacklist.
- Modem controls permit named operations only. Requests for absent legacy
  services may remain denied. Running RIL does not prove telephony correctness.
- Dedicated partition/directory types preserve maintenance boundaries; retire
  the redundant proinfo probe rather than granting raw partition access.
- Two existing regular NA77_005 records have a separate type and permit FSD
  writes; other protect records retain their read-only contract. GSM can remove
  stale radio symlinks during reset. SIM detection/mobile data passed afterward.
  No raw partition write or absent-record creation grant is added.
- Camera configuration/dump markers remain absent by default. Generated paths
  preserve opt-in/default behavior and do not migrate calibration data.
- BIP cannot read platform-private DNS properties. The recovered AP path emits
  a no-DNS response; BIP-specific modem acceptance remains untested despite
  working ordinary SIM detection/mobile data.
- Optional DSU metadata probes take the normal non-DSU fallback when denied.
  Third-party apps remain unable to inspect arbitrary kernel/proc information.

## Validation

```bash
source build/envsetup.sh
lunch lineage_achilles6_row_data-userdebug
m -j4 selinux_policy
```

Development passed 271 strict host policy checks and actual-OTA validation.
The historical scripts depended on private audit fixtures and are not claimed
as portable tests here. The integration repo supplies a smaller, explicitly
scoped portable verification suite. Review AVCs by operation and contract;
an empty AVC log is not a release criterion. New Android versions need review.
