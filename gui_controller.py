# User-Defined Access Protection/Exploit Prevention Rule Merger - GUI Functions
# v0.5.5 - 2021/02/16 - kurt.sels@secutec.be
import tkinter
import tkinter.ttk
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
import os
from copy import deepcopy
from epo_policy import EpoPolicy

from sys import getsizeof


class Controller(object):
    def __init__(self):
        # All policies
        self.source_policies = []
        self.destination_policies = []
        # Selected policy
        self.source_policy = None
        self.destination_policy = None

        self.all_rules_cb = []
        self.unwanted_rule_names = []

    # Source policy specific: open_file and save policy in global variable
    def open_source(self, txt, lst, cbb):
        txt.delete(1.0, tkinter.END)
        # lst.delete(1.0, tkinter.END)
        cbb['values'] = []
        cbb.set('')

        self.source_policy = Controller.open_file(txt, cbb)

        # Turn all policies in the main policy file, which could contain multiple, into individual policies.
        for index, policy in enumerate(self.source_policy.defined_policies):
            copy_policy = deepcopy(self.source_policy)
            copy_policy.convert_to_single_policy(copy_policy.defined_policies[index])
            self.source_policies.append(copy_policy)

        self.select_source_policy(cbb, lst)
        # self.show_source_rules(lst, self.source_policy)

    def show_source_rules(self, lst, source_policy):
        lst.delete(1.0, tkinter.END)
        self.all_rules_cb.clear()
        # Populate textbox with Custom Rules
        if len(source_policy.custom_settings) == 0:
            lst.insert(tkinter.END, "No Custom Rules Found")
        else:
            for rule in source_policy.custom_settings:
                # Create checkbox for every rule
                style = tkinter.ttk.Style()
                style.configure('TCheckbutton', background="white")
                cb = tkinter.ttk.Checkbutton(text=EpoPolicy.get_rule_name(rule), style="TCheckbutton")
                cb.state(['selected', '!alternate'])
                # Insert in textbox
                lst.window_create(tkinter.END, window=cb)
                lst.insert(tkinter.END, "\n")
                # Add to list of all rule Checkbuttons
                self.all_rules_cb.append(cb)

    # Destination policy specific: open_file and save policy in global variable
    def open_destination(self, txt, lst, cbb):
        txt.delete(1.0, tkinter.END)
        lst.delete(0, tkinter.END)

        self.destination_policy = Controller.open_file(txt, cbb)

        # Populate listbox with Custom Rule names
        if len(self.destination_policy.custom_settings) == 0:
            lst.insert(tkinter.END, "No Custom Rules Found")
        else:
            for rule in self.destination_policy.custom_settings:
                lst.insert(tkinter.END, EpoPolicy.get_rule_name(rule))

    # Find which rules are unwanted, not checked, and add them to the variable
    def get_unwanted_rules(self):
        self.unwanted_rule_names = []

        for cb in self.all_rules_cb:
            if not cb.instate(['selected']):
                self.unwanted_rule_names.append(cb.cget('text'))

    # Save the combined policy to a new XML file
    def save_policy(self):
        if self.source_policy is not None and self.destination_policy is not None:
            if self.source_policy.policy_type == self.destination_policy.policy_type:
                file = filedialog.asksaveasfile(filetypes=[('xml files', '*.xml'), ('all files', '*.*')])
                if file is not None:
                    # Copy source policy to not make permanent changes
                    copy_source = deepcopy(self.source_policy)
                    # Filter out rules already present in destination
                    copy_source.filter_custom_rules(self.destination_policy)
                    # Filter out unwanted rules
                    self.get_unwanted_rules()
                    copy_source.filter_unwanted_rules(self.unwanted_rule_names)
                    # add remaining rules to the destination policy
                    self.destination_policy.add_custom_rules(copy_source)
                    # Write the combined policy to a file
                    self.destination_policy.file.write(file.name)

                    message = "File Saved Under: " + file.name
                    messagebox.showinfo("File Saved", message)
            else:
                messagebox.showerror("Merge Error", "You are trying to merge apples into oranges.")
        else:
            messagebox.showerror("No Policy Found", "Either the source policy or the destination policy is missing.")

    def select_source_policy(self, cbb, lst):
        # TODO:
        self.source_policy = self.source_policies[cbb.current()]
        self.show_source_rules(lst, self.source_policy)

    # Read a Policy XML file & load the rules into a listbox and the name into a textbox
    @classmethod
    def open_file(cls, txt, cbb):
        file = filedialog.askopenfile(mode='r', filetypes=[('xml files', '*.xml'), ('all files', '*.*')])

        if file is not None:
            # Create EpoPolicy Object from .xml
            policy = EpoPolicy(file.name)
            # TODO? Handle .xml containing multiple policies
            # if policy.defined_policies.__len__() > 1:
            #    split_multi(policy)
            # Populate policy name textbox
            policy_info = policy.server_id + " > " + policy.policy_type + " (" + os.path.basename(file.name) + ")"
            txt.insert(tkinter.END, policy_info)

            # Populate combobox with the name of all the policies (if file contains multiple ones)
            cbb_values = []
            for policy_name in policy.defined_policies_names:
                cbb_values.append(policy_name)
            cbb['values'] = cbb_values
            cbb.current(0)

            return policy
