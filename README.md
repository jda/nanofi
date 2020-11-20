# µFi: a small UniFi controller
NOTE: no controller yet, just libs for handling inform. Making public early as [pixiedust](https://github.com/jda/pixiedust) needs this.

## Design Principles
1. Small systems
2. Low complexity

## Resources
UniFi inform protocol: https://jrjparks.github.io/unofficial-unifi-guide/

## Use-cases
* Run controller on small OpenWRT router
* Unattended system to upgrade devices prior to deployment (if old SW, adopt, upgrade, default).

## Protocol notes
Controller returns 404 on inform if device has not been adopted.

## Questions
* How does controller generate new shared secrets?
