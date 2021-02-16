# User-Defined Access Protection/Exploit Prevention Rule Merger - GUI
# v0.5.5 - 2021/02/16 - kurt.sels@secutec.be
import tkinter
import tkinter.ttk
import gui_controller as gc


# Main program: Create GUI and couple functions
def main():
    # Controller
    controller = gc.Controller()

    # Main Window Definition
    window = tkinter.Tk()
    window.title("AP EP Rule Merger")
    window.minsize(200, 100)
    window.resizable(False, False)

    # Widget Definitions
    lbl_source = tkinter.Label(window, text="Source Policy:")
    lbl_destination = tkinter.Label(window, text="Destination Policy:")
    lbl_source_rule = tkinter.Label(window, text="New Custom Rules (source)")
    lbl_destination_rule = tkinter.Label(window, text="Existing Custom Rules (destination)")

    txt_source = tkinter.Text(window)
    txt_destination = tkinter.Text(window)

    txt_source_rule = tkinter.Text(window)
    lst_destination_rule = tkinter.Listbox(window)

    # TODO:
    cbb_source = tkinter.ttk.Combobox(window, values=[])
    cbb_destination = tkinter.ttk.Combobox(window, values=[])

    sb_source = tkinter.Scrollbar(window)
    sb_destination = tkinter.Scrollbar(window)

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
    # TODO
    cbb_source.grid(row=3, column=1, padx=5, pady=5, columnspan=3, sticky=tkinter.E)

    txt_source_rule.grid(row=4, column=0, padx=5, pady=5, columnspan=4)
    txt_source_rule.configure(width=67, height=10)
    txt_source_rule.configure(yscrollcommand=sb_source.set)

    sb_source.grid(row=4, column=4, sticky=tkinter.NS)
    sb_source.configure(command=txt_source_rule.yview)

    lbl_destination_rule.grid(row=5, column=0, padx=5, pady=5, sticky=tkinter.W)
    # TODO
    cbb_destination.grid(row=5, column=1, padx=5, pady=5, columnspan=3, sticky=tkinter.E)

    lst_destination_rule.grid(row=6, column=0, padx=5, pady=5, columnspan=4)
    lst_destination_rule.configure(width=90)
    lst_destination_rule.configure(yscrollcommand=sb_destination.set)

    sb_destination.grid(row=6, column=4, sticky=tkinter.NS)
    sb_destination.configure(command=lst_destination_rule.yview)

    btn_merge.grid(row=7, column=3, padx=5, pady=5, sticky=tkinter.E)

    # cbb_example.grid(row=8, column=0, padx=5, pady=5, sticky=tkinter.W)

    # Widget Configuration
    btn_source.configure(command=lambda: controller.open_source(txt_source, txt_source_rule, cbb_source))
    btn_destination.configure(command=lambda: controller.open_destination(txt_destination, lst_destination_rule,
                                                                          cbb_destination))
    btn_merge.configure(command=lambda: controller.save_policy())

    cbb_source.bind("<<ComboboxSelected>>", lambda x: controller.select_source_policy(cbb_source, txt_source_rule))

    window.mainloop()


# Start Program
if __name__ == '__main__':
    main()
