# User-Defined Access Protection/Exploit Prevention Rule Merger - GUI Functions
# v0.5.1 - 2020/03/25 - kurt.sels@secutec.be
import tkinter
import tkinter.ttk
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
import os
from copy import deepcopy
from epo_policy import EpoPolicy


class Controller(object):
    def __init__(self):
        self.source_policy = None
        self.destination_policy = None
        self.all_rules_cb = []
        self.unwanted_rule_names = []

    # Source policy specific: open_file and save policy in global variable
    def open_source(self, txt, lst):
        txt.delete(1.0, tkinter.END)
        lst.delete(1.0, tkinter.END)

        self.source_policy = Controller.open_file(txt, lst)

        # Populate textbox with Custom Rules
        if len(self.source_policy.custom_settings) == 0:
            lst.insert(tkinter.END, "No Custom Rules Found")
        else:
            for rule in self.source_policy.custom_settings:
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
    def open_destination(self, txt, lst):
        txt.delete(1.0, tkinter.END)
        lst.delete(0, tkinter.END)

        self.destination_policy = Controller.open_file(txt, lst)

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

    # Read a Policy XML file & load the rules into a listbox and the name into a textbox
    @classmethod
    def open_file(cls, txt, lst):
        file = filedialog.askopenfile(mode='r', filetypes=[('xml files', '*.xml'), ('all files', '*.*')])

        if file is not None:
            # Create EpoPolicy Object from .xml
            policy = EpoPolicy(file.name)
            # Populate policy name textbox
            policy_info = policy.server_id + ">" + policy.policy_name + " (" + os.path.basename(file.name) + ")"
            txt.insert(tkinter.END, policy_info)

            return policy
