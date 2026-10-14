CONTROL Infinite Respec v0.1.0
==============================

PURPOSE
-------
Keeps Respec Items from being consumed by Talent, Melee, and Ability respecs.
You still need to own at least 1 legitimate Respec Item for the game's normal
"can respec" check to pass. After a successful respec, the item should remain.

REQUIREMENT
-----------
The f2g/ftg DLL Mod Loader for CONTROL Resonant, configured to load DLLs from:
    CONTROL Resonant\crmods\

INSTALL
-------
1. Make sure the DLL Mod Loader is already installed.
2. Extract this ZIP into the CONTROL Resonant game folder, next to
   CONTROLResonant.exe.
3. You should end up with:
       CONTROL Resonant\crmods\ControlInfiniteRespec.dll
4. Launch the game.

VERIFY
------
On launch the mod creates:
    CONTROL Resonant\crmods\ControlInfiniteRespec.log

A successful startup ends with:
    ACTIVE - all three respec consumption paths patched.

Test with a legitimate Respec Item. The UI should still require the item, but
its count should not decrease after Talent, Melee, or Ability respecs.

HOW IT WORKS
------------
This build was made from the executable data collected from the user's current
CONTROL Resonant build (SHA-256 of researched EXE:
2c6575be23ea9a2d316fb530d094773b371ab1da6344aa7a97b8cc2dabaf1ca0).

It does not hard-code absolute addresses. It signature-scans executable sections
for all three verified respec spending paths. Only if all three signatures are
found exactly once does it patch anything.

The patches are intentionally small:
- Talent respec: currency-spend amount 1 -> 0
- Melee respec: currency-spend amount 1 -> 0
- Ability respec: currency-spend amount 1 -> 0
- Ability respec: suppress its separate cached item-count decrement

The normal affordability/ownership check is left untouched.

If a game update changes the code and any signature is missing or ambiguous,
the mod applies no patches and records the failure in its log.

UNINSTALL
---------
Delete:
    crmods\ControlInfiniteRespec.dll
    crmods\ControlInfiniteRespec.log

The mod changes process memory only. It does not modify CONTROLResonant.exe.

STATUS
------
v0.1.0 is the first test build. Its signatures and patch locations were checked
against the collected executable windows, but the DLL cannot be run against the
actual game in the build environment. The in-game respec test is therefore the
final validation step.
