# Defensive signature coverage catalog

`signatures.json` stores SHA-256 release records under `entries` and a separate
client coverage inventory under `clients`. Hash records are accepted only when
there is a 64-character SHA-256 digest, a version, evidence text, an HTTPS source
on the scanner's allow-list, and a supported verification status. Duplicate
hashes are rejected. Metadata and package identifiers are never treated as
cryptographic signatures.

## Verified project identifiers

The scanner recognizes exact Fabric metadata IDs and package prefixes sourced
from the projects' own repositories:

- Meteor Client: `meteor-client`, `meteordevelopment.meteorclient`
- LiquidBounce: `liquidbounce`, `net.ccbluex.liquidbounce`
- Wurst: `wurst`, `net.wurstclient`

These identifiers produce **Manual Review** findings. A JAR can forge metadata
or reuse a package name, so they do not prove the artifact is authentic or that
the client was used. A runtime package match is also a review lead unless a
verified artifact is correlated to the process.

## Hash coverage

Six Meteor Client release JARs have source-derived SHA-256 records. Five are
marked `OfficialSourceHashed`; Meteor 1.21.11 build 86 is additionally marked
`IndependentlyVerified` based on the catalog's cited static-analysis record.
There are no verified DLL signatures and no hashes for the other listed clients.
Do not treat a missing match as evidence that a client is absent.

## Sources

- Meteor official metadata and source package: <https://github.com/MeteorDevelopment/meteor-client/blob/master/src/main/resources/fabric.mod.json> and <https://github.com/MeteorDevelopment/meteor-client/blob/master/src/main/java/meteordevelopment/meteorclient/MeteorClient.java>
- Meteor release archive: <https://meteorclient.com/archive>
- LiquidBounce official metadata and source package: <https://github.com/CCBlueX/LiquidBounce/blob/nextgen/src/main/resources/fabric.mod.json> and <https://github.com/CCBlueX/LiquidBounce/blob/nextgen/src/main/kotlin/net/ccbluex/liquidbounce/features/module/ModuleManager.kt>
- Wurst official metadata and source package: <https://github.com/Wurst-Imperium/Wurst7/blob/master/src/main/resources/fabric.mod.json> and <https://github.com/Wurst-Imperium/Wurst7/blob/master/src/main/java/net/wurstclient/WurstClient.java>
- Fabric metadata specification: <https://fabricmc.net/wiki/documentation:fabric_mod_json>

The catalog includes an entry for each client requested in the v7.0 scope. For
clients without source-verified signatures or stable identifiers, the entry
explicitly says no verified client-specific detection is catalogued.

## Doomsday coverage review (2026-10-16)

The official [DoomsDay product page](https://doomsdayclient.com/) describes a
cross-version utility mod with ghost-client functionality; its [features
page](https://doomsdayclient.com/features) lists gameplay features and a loader
removal UI. The public pages do not publish a stable package/class identifier,
metadata ID, artifact digest, agent name, or native module signature. The site
also advertises loader filename randomization, so filename matching is not
reliable. These pages establish product context only and are not treated as
technical signatures.

The community `LumeTools/ddchecker` repository describes an invasive JVMTI/DLL
injection proof of concept that enumerates loaded classes. It is not a source of
Doomsday-specific class identifiers, and reproducing its attach/injection
approach would violate this scanner's passive-only inspection policy. No
Doomsday-specific detector is currently verified. The scanner reports this as
insufficient coverage instead of treating generic modules or agents as a
Doomsday match.

