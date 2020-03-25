## Info
v0.5.1 - kurt.sels@secutec.be

## Description
A tool allowing you to merge McAfee ENS Access Protection or Exploit Prevention rules from one policy into another.

## How to use
* Export your source policy, containing the rules you want to add, to a .xml file.
* Export your destination policy, missing the rules from the source policy, to a .xml file.
* Run the APEPRuleMerger programme
* Load the source and destination policy
* Merge the two policies into one.
* Re-import the merged rule into the ePO, it will overwrite the original destination policy now with the rules from the source added.

*(Note: pre-existing rules and any other policy changes remain intact)*

## TODO
* ~~Allow selecting specific rules to add instead of always adding all rules at once.~~
  * Clean up code.
    * ~~Split up gui file into gui, interface only, and gui_controller, function and interaction with logic.~~
  * Select all / deselect all for convenience.
* Add support for policy .xml files containing multiple policies in one file.
* Integrate with Web API and/or OpenDXL to download policies from ePO<sup>1</sup>.

<sup>1</sup>*Requires multiple policies in one file support.*

## Changelog
0.4.8 - GUI ready for selecting which rules to merge; functionality not in logic code yet.  
0.5.0 - Allow selecting specific rules to add instead of always adding all rules.  
0.5.1 - Split up gui into gui and gui_controller, pseudo-MVC