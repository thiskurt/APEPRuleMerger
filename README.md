# Info
v0.4.7 - kurt.sels@secutec.be

# Description
A tool allowing you to merge McAfee ENS Access Protection or Exploit Prevention rules from one policy into another.

# How to use

* Export your source policy, containing the rules you want to add, to a .xml file.
* Export your destination policy, missing the rules from the source policy, to a .xml file.
* Run the APEPRuleMerger programme
* Load the source and destination policy
* Merge the two policies into one.
* Re-import the merged rule into the ePO, it will overwrite the original destination policy now with the rules from the source added.

(pre-existing rules and any other policy changes remain intact)
