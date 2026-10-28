# Hardware Keymaster

Installs the matching stock Beanpod executable as the standard default HAL.
The service path retains the platform SELinux exec label, early_hal class,
system user and system/drmrpc groups. No second software default is packaged.

Source firmware: TB_X606X_S301085_230919_BMP.zip (SHA256
`de476c26c3c4f2da47cbe83113286720ae55ad854b9ebf35a1e4cf0ef31b7c87`).
Beanpod service SHA256:
`ac5bf57b05d791d900589d3786289077ac9ed666eae4af9f6101c734242a38a0`.
The executable is excluded from Git; use integration prepare_blobs.py.

Software Keymaster produced incompatible keys during bring-up. The tested
hardware backend allows Android FBE and matching TWRP PIN decryption. Do not
switch backends on existing encrypted userdata as an ordinary update. A trusted
environment log is not remote-attestation or overall security certification.
