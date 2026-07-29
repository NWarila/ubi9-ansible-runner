# Technical Debt

This register records accepted maintenance obligations that need an explicit
exit condition.

## TD-1: Ansible Core 2.16 Stream

- Status: Open
- Related decision:
  [ADR-0003](decision-records/repo/0003-version-ansible-core-streams.md)
- Launch floor: `ansible-core` `2.16.19`

The initial runtime stream is `2.16` because its first consumers manage
RHEL 8 and Rocky Linux 8 targets whose platform Python constrains controller
compatibility. The stream is past its ordinary community support window, so its
continued suitability is an explicit exception rather than a general version
policy.

Maintainers must monitor upstream releases and security advisories to determine
whether the 2.16 stream continues to receive acceptable security fixes. Every
proposed dependency refresh must preserve the `>=2.16.19,<2.17` boundary and
must be assessed against known vulnerabilities before publication.

Exit this exception when either:

1. The dependency on RHEL 8 and Rocky Linux 8 targets ends, allowing consumers
   to move to a supported stream; or
2. The 2.16 stream retires or stops receiving acceptable security fixes.

At either exit, move consumers to a supported stream or stop publishing the
2.16 line. Do not silently continue an unmaintained stream.
