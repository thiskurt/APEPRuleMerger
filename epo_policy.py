# User-Defined Access Protection/Exploit Prevention Rule Merger - Logic/Class
# v0.5.5 - 2021/02/16 - kurt.sels@secutec.be
import xml.etree.ElementTree as et


class EpoPolicy(object):
    __slots__ = ['file', 'file_root', 'custom_settings', 'custom_settings', 'custom_objects', 'defined_policies',
                 'defined_policies_names', 'server_id', 'policy_name', 'policy_feature', 'policy_type', 'highest_EP_rule_id']

    def __init__(self, file_name):
        """
        :param file_name: Location of the .xml file of a McAfee policy (single policy only)
        """
        self.file = et.parse(file_name)
        self.file_root = self.file.getroot()
        self.custom_settings = []               # Custom rule settings, ie actual definition
        self.custom_objects = []                # Custom rule object referencing the above
        self.defined_policies = []              # All defined policy objects; mainly needed by child class multi policy
        self.defined_policies_names = []        # Names of all defined policies

        self.server_id = "Not Found"            # Server id
        self.policy_name = "Not Found"          # Policy name
        self.policy_feature = "Not Found"
        self.policy_type = "Not Found"          # Policy type info
        self.highest_EP_rule_id = 20000         # Highest custom EP rule ID

        self.find_custom_rules()

    def re_init(self):
        """TODO: Clear everything when switching to single policy"""
        self.custom_settings = []               # Custom rule settings, ie actual definition
        self.custom_objects = []                # Custom rule object referencing the above
        self.defined_policies = []              # All defined policy objects; mainly needed by child class multi policy
        self.defined_policies_names = []        # Names of all defined policies

        self.server_id = "Not Found"            # Server id
        self.policy_name = "Not Found"          # Policy name
        self.policy_feature = "Not Found"
        self.policy_type = "Not Found"          # Policy type info
        self.highest_EP_rule_id = 20000         # Highest custom EP rule ID

        self.find_custom_rules()

    def find_custom_rules(self):
        """Find and set all the custom AP/EP rules and also the server_id, policy_name and policy_type"""
        # Save the source policy's custom AP/EP settings and policy objects to two lists
        for child in self.file_root:
            # Find custom AP/EP settings by checking for the tag 'EPOPolicySettings'
            if child.tag == 'EPOPolicySettings':
                for setting in child.iter('Setting'):
                    # Custom AP Rules | Identified by value Custom
                    if setting.get('name') in ('RuleType', 'appProtectionType') and setting.get('value') == 'Custom':
                        self.custom_settings.append(child)
                    # Custom EP Rules | Identified by having an ID 20000 or higher
                    if setting.get('name') == "SignatureID" and setting.get('value').startswith('20'):
                        # Keep track of highest EP rule ID
                        self.highest_EP_rule_id = max(self.highest_EP_rule_id, int(setting.get('value')))
                        self.custom_settings.append(child)

            # Find the matching custom AP/EP policy object by comparing its text with the custom AP setting name value
            if child.tag == 'EPOPolicyObject':
                self.defined_policies.append(child)                     # Keep a record of every policy
                self.defined_policies_names.append(child.get('name'))   # Keep a record of their names (see to do below)

                # TODO: Wouldn't it be better to keep this as a dictionary for all of them or something?
                self.server_id = child.get('serverid')      # Save server ID    All this will only store the last policy
                self.policy_name = child.get('name')        # Save policy name
                self.policy_type = child.get('typeid')      # Save policy type info
                self.policy_feature = child.get('featureid')
                for policy_object in child.iter('PolicySettings'):
                    for customAP in self.custom_settings:
                        if customAP.get('name') == policy_object.text:
                            # Add it to list of custom policy objects
                            self.custom_objects.append(policy_object)

    def filter_custom_rules(self, other_policy):
        """ Remove all custom AP/EP rules (from the source) that also exist in the other policy (by name)
        :param other_policy: Other policy to compare itself with
        """
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

    def filter_unwanted_rules(self, unwanted_rule_names):
        """ Remove unwanted custom rules
        :param unwanted_rule_names: List of strings containing the names of unwanted rules.
        """
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

    def add_custom_rules(self, other):
        """ Add the other policy(ie source policy)'s custom AP/EP rules to yourself(ie destination policy)
        :param other: Other policy from which to copy the custom rules.
        """

        # Add the remaining custom AP rules from the source policy to the destination policy
        i = 0
        added = False

        for child in self.file_root:
            # Find the first AP/EP setting
            if child.tag == 'EPOPolicySettings' and not added:
                # Add the remaining source AP/EP settings before this one
                for custom in reversed(other.custom_settings):
                    # Change the ID of the custom rule, if an EP rule, to avoid duplicates
                    for setting in custom.iter('Setting'):
                        if setting.get('name') == 'SignatureID':
                            self.highest_EP_rule_id = self.highest_EP_rule_id + 1
                            setting.set('value', str(self.highest_EP_rule_id))
                    # Insert
                    self.file_root.insert(i, custom)
                added = True

            # Find the first AP/EP Policy Object
            if child.tag == 'EPOPolicyObject':
                for grandchild in child:
                    # Find the first Built in AP policy object
                    if grandchild.tag == 'PolicySettings' and not added:
                        #  Add the remaining source AP Policy Object before that one
                        for custom in reversed(other.custom_objects):
                            self.file_root[i].insert(1, custom)
                            added = True
            i = i + 1

    def convert_to_single_policy(self, chosen_policy):
        """ Convert multi policy to a single policy
        :type chosen_policy: Single policy to extract. (Easy to get one by index: [self].defined_policies[i])
        :return !No return. Policy Object will BECOME a SINGLE policy, not return one
        """
        redundant_policies = []
        redundant_rules = []

        # Remove redundant policies
        for child in self.file_root.iter('EPOPolicyObject'):
            if child != chosen_policy:
                redundant_policies.append(child)
        for redundant in redundant_policies:
            self.file_root.remove(redundant)

        # Remove every rule not in the chosen policy
        for rule_setting in self.file_root.iter('EPOPolicySettings'):
            relevant = False
            for relevant_rule in chosen_policy.iter('PolicySettings'):
                if rule_setting.get('name') == relevant_rule.text:
                    relevant = True
            if not relevant:
                redundant_rules.append(rule_setting)
        for redundant in redundant_rules:
            self.file_root.remove(redundant)
        # self.find_custom_rules()  # To reset info; Seems stupid to loop through it again just for that.
        # TODO:
        self.re_init()

    @classmethod
    def get_rule_name(cls, setting):
        """ Return the rule name from a setting element
        :param setting: A setting as an element from a xml.etree.ElementTree
        :return: The name of a given rule as a string
        """
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
        """ Return the rule from a setting element
        :param setting: A setting as an element from a xml.etree.ElementTree
        :return: The note giving info about a rule as a string
        """
        for sections in setting:
            for value in sections:
                if value.get("name") == "SignatureNotes":  # EP Signatures
                    return value.get("value")
                if value.get("name") == "appProtectionNotes":  # EP Application Protection Rules
                    return value.get("value")
