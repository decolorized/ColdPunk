"""Minimal fake tkinter for test_mwlink_gui.py: enough of Tk / widgets /
variables to construct mwlink_gui.App headless and drive its handlers. Every
widget records its options, so tests can read button states, label texts, the
console and the clipboard. Tk calls from a non-Tk thread raise, like real Tk."""
import time
import threading


class TclError(Exception):
    pass


ALL_WIDGETS = []


class Variable:
    def __init__(self, master=None, value=None):
        self._v = value

    def get(self):
        return self._v

    def set(self, v):
        self._v = v


class StringVar(Variable):
    def __init__(self, master=None, value=""):
        super().__init__(master, value)


class BooleanVar(Variable):
    def __init__(self, master=None, value=False):
        super().__init__(master, value)

    def get(self):
        return bool(self._v)


class IntVar(Variable):
    def __init__(self, master=None, value=0):
        super().__init__(master, value)


class Widget:
    def __init__(self, master=None, **kw):
        self.master = master
        self.opts = dict(kw)
        if "state" not in self.opts:
            self.opts["state"] = "normal"
        ALL_WIDGETS.append(self)

    # geometry
    def grid(self, **kw):
        return None

    def pack(self, **kw):
        return None

    # options
    def configure(self, **kw):
        self.opts.update(kw)

    config = configure

    def __setitem__(self, k, v):
        self.opts[k] = v

    def __getitem__(self, k):
        return self.opts.get(k)

    def cget(self, k):
        return self.opts.get(k)

    def yview(self, *a):
        return None

    def set(self, *a):
        return None

    # helpers for tests
    def text(self):
        return self.opts.get("text", "")

    def invoke(self):
        if self.opts.get("state") == "disabled":
            return "disabled"
        cmd = self.opts.get("command")
        if cmd:
            return cmd()


class Text(Widget):
    def __init__(self, master=None, **kw):
        super().__init__(master, **kw)
        self.content = []          # list of (tag, text)

    def insert(self, index, text, tag=None):
        if self.opts.get("state") == "disabled":
            return                  # real Tk ignores inserts into a disabled Text
        self.content.append((tag, text))

    def delete(self, a, b=None):
        if self.opts.get("state") == "disabled":
            return
        self.content = []

    def get(self, a, b=None):
        return "".join(t for _tag, t in self.content)

    def see(self, index):
        pass

    def tag_configure(self, *a, **kw):
        pass


class Tk(Widget):
    def __init__(self):
        super().__init__(None)
        self._after = []            # (due, seq, fn, args)
        self._seq = 0
        self._protocols = {}
        self.destroyed = False
        self._lock = threading.Lock()

    def title(self, t=None):
        self.opts["title"] = t

    def geometry(self, g=None):
        pass

    def minsize(self, w, h):
        pass

    def protocol(self, name, fn):
        self._protocols[name] = fn

    def after(self, ms, fn=None, *args):
        if threading.current_thread() is not threading.main_thread():
            # Real Tk would raise "main thread is not in main loop" here.
            raise RuntimeError("after() called from a non-Tk thread")
        self._seq += 1
        self._after.append((time.monotonic() + ms / 1000.0, self._seq, fn, args))
        return "after#%d" % self._seq

    def destroy(self):
        self.destroyed = True

    def clipboard_clear(self):
        self.clipboard = ""

    def clipboard_append(self, text):
        self.clipboard = getattr(self, "clipboard", "") + text

    def run_for(self, seconds):
        """Fake mainloop: run due after() callbacks for `seconds`."""
        end = time.monotonic() + seconds
        while time.monotonic() < end and not self.destroyed:
            now = time.monotonic()
            due = [a for a in self._after if a[0] <= now]
            self._after = [a for a in self._after if a[0] > now]
            for _d, _s, fn, args in sorted(due, key=lambda a: a[1]):
                fn(*args)
            time.sleep(0.01)

    def mainloop(self):
        while not self.destroyed:
            self.run_for(0.1)


class Frame(Widget):
    pass


class Label(Widget):
    pass


class Button(Widget):
    pass


class Scrollbar(Widget):
    pass


class Toplevel(Widget):
    def title(self, t=None):
        self.opts["title"] = t

    def destroy(self):
        self.destroyed = True
