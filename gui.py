# User-Defined Access Protection/Exploit Prevention Rule Merger - GUI
# v0.4.7 - 2020/01/13 - kurt.sels@secutec.be
import tkinter
import tkinter.ttk
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
import os
from epo_policy import EpoPolicy

# Variables for policies
source_policy = None
destination_policy = None


# Function Definitions
# Read a Policy XML file & load the rules into a listbox and the name into a textbox
def open_file(txt, lst):
    file = filedialog.askopenfile(mode='r', filetypes=[('xml files', '*.xml'), ('all files', '*.*')])
    txt.delete(1.0, tkinter.END)
    lst.delete(0, tkinter.END)

    if file is not None:
        # Create EpoPolicy Object from .xml
        policy = EpoPolicy(file.name)
        # Populate policy name textbox
        policy_info = policy.server_id + ">" + policy.policy_name + " (" + os.path.basename(file.name) + ")"
        txt.insert(tkinter.END, policy_info)
        # Populate listbox with Custom Rule names
        if len(policy.custom_settings) == 0:
            lst.insert(tkinter.END, "No Custom Rules Found")
        else:
            for rule in policy.custom_settings:
                lst.insert(tkinter.END, EpoPolicy.get_rule_name(rule))

        return policy


# Source policy specific: open_file and save policy in global variable
def open_source(txt, lst):
    global source_policy
    source_policy = open_file(txt, lst)


# Destination policy specific: open_file and save policy in global variable
def open_destination(txt, lst):
    global destination_policy
    destination_policy = open_file(txt, lst)


# Save the combined policy to a new XML file
def save_file():
    if source_policy is not None and destination_policy is not None:
        if source_policy.policy_type == destination_policy.policy_type:
            file = filedialog.asksaveasfile(filetypes=[('xml files', '*.xml'), ('all files', '*.*')])
            if file is not None:
                # Filter out rules already present & add remaining rules to the destination policy
                source_policy.filter_custom_rules(destination_policy)
                destination_policy.add_custom_rules(source_policy)

                # Write the combined policy to a file
                destination_policy.file.write(file.name)

                message = "File Saved Under: " + file.name
                messagebox.showinfo("File Saved", message)
        else:
            messagebox.showerror("Merge Error", "You are trying to merge apples into oranges.")
    else:
        messagebox.showerror("No Policy Found", "Either the source policy or the destination policy is missing.")


# Main program: Create GUI and couple functions
def main():
    # Main Window Definition
    window = tkinter.Tk()
    window.title("AP EP Rule Merger")
    # window.iconbitmap("mcafee.ico")
    window.minsize(200, 100)
    window.resizable(False, False)

    # Widget Definitions
    lbl_source = tkinter.Label(window, text="Source Policy:")
    lbl_destination = tkinter.Label(window, text="Destination Policy:")
    lbl_source_rule = tkinter.Label(window, text="New Custom Rules (source)")
    lbl_destination_rule = tkinter.Label(window, text="Existing Custom Rules (destination)")

    txt_source = tkinter.Text(window)
    txt_destination = tkinter.Text(window)

    lst_source_rule = tkinter.Listbox(window)
    lst_destination_rule = tkinter.Listbox(window)

    btn_source = tkinter.Button(window, text="Load File")
    btn_destination = tkinter.Button(window, text="Load File")
    btn_merge = tkinter.Button(window, text="Merge Policies")

    tsp_separator = tkinter.ttk.Separator(window, orient=tkinter.HORIZONTAL)

    # Widget Placement, Sizing & Look
    lbl_source.grid(row=0, column=0, padx=5, pady=5, sticky=tkinter.W)
    txt_source.grid(row=0, column=1, padx=5, pady=5, columnspan=2)
    txt_source.configure(height=1, width=30)
    btn_source.grid(row=0, column=3, padx=5, pady=5, sticky=tkinter.E)

    lbl_destination.grid(row=1, column=0, padx=5, pady=5, sticky=tkinter.W)
    txt_destination.grid(row=1, column=1, padx=5, pady=5, columnspan=2)
    txt_destination.configure(height=1, width=30)
    btn_destination.grid(row=1, column=3, padx=5, pady=5, sticky=tkinter.E)

    tsp_separator.grid(row=2, column=0, padx=5, pady=5, columnspan=4, sticky=tkinter.EW)

    lbl_source_rule.grid(row=3, column=0, padx=5, pady=5, sticky=tkinter.W)

    lst_source_rule.grid(row=4, column=0, padx=5, pady=5, columnspan=4)
    lst_source_rule.configure(width=90)

    lbl_destination_rule.grid(row=5, column=0, padx=5, pady=5, sticky=tkinter.W)

    lst_destination_rule.grid(row=6, column=0, padx=5, pady=5, columnspan=4)
    lst_destination_rule.configure(width=90)

    btn_merge.grid(row=7, column=3, padx=5, pady=5, sticky=tkinter.E)

    # Widget Configuration
    btn_source.configure(command=lambda: open_source(txt_source, lst_source_rule))
    btn_destination.configure(command=lambda: open_destination(txt_destination, lst_destination_rule))
    btn_merge.configure(command=lambda: save_file())

    window.mainloop()


# Start Program
if __name__ == '__main__':
    main()