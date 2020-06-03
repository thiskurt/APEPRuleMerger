# User-Defined Access Protection/Exploit Prevention Rule Merger - Logic/Class
# v0.5.2 - 2020/06/03 - kurt.sels@secutec.be
# TODO: Clean up dirty fix for EP rule ID conflict bug
import xml.etree.ElementTree as et


class EpoPolicy(object):
    def __init__(self, file_name):
        self.file = et.parse(file_name)
        self.file_root = self.file.getroot()
        self.custom_settings = []               # Custom rule settings, ie actual definition
        self.custom_objects = []                # Custom rule object referencing the above
        self.server_id = "Not Found"            # Server id
        self.policy_name = "Not Found"          # Policy name
        self.policy_type = "Not Found"          # Policy type info
        self.highest_EP_rule_id = 20000

        self.find_custom_rules()

    # Find and set all the custom AP/EP rules and also the server_id, policy_name and policy_type
    def find_custom_rules(self):
        # Save the source policy's custom AP/EP settings and policy objects to two lists
        for child in self.file_root:
            # Find custom AP/EP settings by checking for the tag 'EPOPolicySettings'
            # & checking if the 'RuleType' or appProtectionType setting is custom
            if child.tag == 'EPOPolicySettings':
                for section in child:
                    for setting in section:
                        if (setting.get('name') == 'RuleType' or setting.get('name') == 'appProtectionType') \
                                and setting.get('value') == 'Custom':
                            # Add it to the list of custom AP settings
                            self.custom_settings.append(child)
                        # For Expert rules there is no indication of it being custom except the ID starting at 20000
                        if setting.get('name') == 'SignatureID' and setting.get('value').startswith('20'):
                            # Keep track of highest EP rule ID
                            if int(setting.get('value')) > self.highest_EP_rule_id:
                                self.highest_EP_rule_id = int(setting.get('value'))
                            # Add it to the list of custom EP settings
                            self.custom_settings.append(child)

            # Find the matching custom AP/EP policy object by comparing its text with the custom AP setting name value
            if child.tag == 'EPOPolicyObject':
                self.server_id = child.get('serverid')  # Save server ID
                self.policy_name = child.get('name')    # Save policy name
                self.policy_type = child.get('typeid')  # Save policy type info
                for grandchild in child:
                    if grandchild.tag == 'PolicySettings':
                        for customAP in self.custom_settings:
                            if customAP.get('name') == grandchild.text:
                                # Add it to list of custom policy objects
                                self.custom_objects.append(grandchild)

    # Remove all custom AP/EP rules (from the source) that also exist in the other policy (ie the destination)
    def filter_custom_rules(self, other_policy):
        # Check by name, which includes the ID, no actual intelligence behind it
        # Just so you can merge from the same source xml again, allows re-using a template policy with added rules
        # (Maybe it is doable to check if everything besides the name is the same too for *exact* duplicates)

        # Make a copy of the custom settings, .copy = by value, because deleting from a list while iterating goes weird
        copy_custom_settings = self.custom_settings.copy()

        for index, own_setting in enumerate(copy_custom_settings):
            for other_setting in other_policy.custom_settings:
                if EpoPolicy.get_rule_name(own_setting) == EpoPolicy.get_rule_name(other_setting):
                    self.custom_settings.remove(own_setting)                            # Delete Custom Setting
                    try:                                                                # Delete corresponding object
                        self.custom_objects.remove(other_policy.custom_objects[index])
                    except (ValueError, Exception):
                        pass

    # Remove unwanted custom rules
    def filter_unwanted_rules(self, unwanted_rule_names):
        if unwanted_rule_names is not None:
            copy_custom_settings = self.custom_settings.copy()
            copy_custom_objects = self.custom_objects.copy()

            for index, setting in enumerate(copy_custom_settings):
                for unwanted in unwanted_rule_names:
                    if EpoPolicy.get_rule_name(setting) == unwanted:
                        self.custom_settings.remove(setting)
                        try:
                            self.custom_objects.remove(copy_custom_objects[index])
                        except (ValueError, Exception):
                            pass

    # Add the other policy(ie source policy)'s custom AP/EP rules to yourself(ie destination policy)
    # TODO: cleanup
    def add_custom_rules(self, other):
        # Add the remaining custom AP rules from the source policy to the destination policy
        i = 0
        j = 0
        added = False
        for child in self.file_root:
            # Find the first AP/EP setting
            if child.tag == 'EPOPolicySettings' and not added:
                # Add the remaining source AP/EP settings before this one
                for custom in reversed(other.custom_settings):
                    # TODO: Cleanup
                    j = j + 1
                    EpoPolicy.change_id_custom_rule(custom, j, self.highest_EP_rule_id)

                    self.file_root.insert(i, custom)
                added = True

            # Find the first AP/EP Policy Object
            if child.tag == 'EPOPolicyObject':
                added = False
                for grandchild in child:
                    # Find the first Built in AP policy object
                    if grandchild.tag == 'PolicySettings' and not added:
                        #  Add the remaining source AP Policy Object before that one
                        for custom in reversed(other.custom_objects):
                            self.file_root[i].insert(1, custom)
                            added = True
            i = i + 1

    # Change the ID of the Custom Rule to avoid duplicates
    # TODO: cleanup
    @classmethod
    def change_id_custom_rule(cls, custom, j, highest_rule):
        for setting in custom.iter('Setting'):
            if setting.get('name') == 'SignatureID':
                setting.set('value', str(highest_rule + j))

    # Return the rule name from a setting element
    @classmethod
    def get_rule_name(cls, setting):
        for sections in setting:
            for value in sections:
                if value.get("name") == "SignatureName":  # EP Signatures
                    return value.get("value")
                if value.get("name") == "appProtectionName":  # EP Application Protection Rules
                    return value.get("value")
                if value.get("name") == "RuleName":  # AP Rule
                    return value.get("value")

    # Return the rule note, ie description, from a setting element
    @classmethod
    def get_rule_note(cls, setting):
        for sections in setting:
            for value in sections:
                if value.get("name") == "SignatureNotes":  # EP Signatures
                    return value.get("value")
                if value.get("name") == "appProtectionNotes":  # EP Application Protection Rules
                    return value.get("value")
