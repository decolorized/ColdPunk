"""Scripted file dialogs: tests set NEXT_OPEN / NEXT_DIR / NEXT_SAVE and read
CALLS to see the options the GUI passed."""
NEXT_OPEN = ""
NEXT_DIR = ""
NEXT_SAVE = ""
CALLS = []


def askopenfilename(**kw):
    CALLS.append(("open", kw))
    return NEXT_OPEN


def askdirectory(**kw):
    CALLS.append(("dir", kw))
    return NEXT_DIR


def asksaveasfilename(**kw):
    CALLS.append(("save", kw))
    return NEXT_SAVE
