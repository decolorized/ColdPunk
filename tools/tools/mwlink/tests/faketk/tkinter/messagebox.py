ANSWER = True
CALLS = []


def askyesno(title, message, **kw):
    CALLS.append(("askyesno", title, message))
    return ANSWER


def showerror(title, message, **kw):
    CALLS.append(("showerror", title, message))


def showinfo(title, message, **kw):
    CALLS.append(("showinfo", title, message))


def showwarning(title, message, **kw):
    CALLS.append(("showwarning", title, message))
