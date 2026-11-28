#!/usr/bin/env python3

import os
import time
import typing

import frida
from frida_tools.application import ConsoleApplication, await_ctrl_c
from frida_tools.cli_formatting import format_diagnostic

ASSETS_DIR = os.path.dirname(os.path.abspath(__file__))
TRACES_DIR = os.path.join(ASSETS_DIR, "traces")
SUPPORTED_ARCHS = ("x64", "arm64")


class AgentExports(typing.Protocol):
    def arch(self) -> str: ...
    def trace(
        self,
        traced_modules: list[str] | None,
        start_spec: str,
        oneshot: bool,
        c_src: str,
    ) -> None: ...
    def end(self) -> None: ...


def read_asset(name: str) -> str:
    """Read asset file content by name"""
    with open(os.path.join(ASSETS_DIR, name)) as fd:
        return fd.read()


def bundle_multiple_c_files(*names: str) -> str:
    """Bundle multiple C files into one bundle"""
    bundle = ""
    for name in names:
        # emit bundle mapping info (for better error messages from the C compiler)
        bundle += f'#line 1 "{name}"\n'
        bundle += read_asset(name)
    return bundle


class TraceApplication(ConsoleApplication):
    def __init__(self):
        self.script: frida.Script | None = None
        self.trace_prefix: str = ""
        self.traced_modules: list[str] | None = None
        self.start_spec: str = ""
        self.multi_run: bool = False
        super().__init__(await_ctrl_c)

    @property
    def agent(self) -> AgentExports:
        return typing.cast(AgentExports, self.script.exports_sync)

    def _usage(self):
        return "%(prog)s [options] [-t MODULE ...] -s START target"

    def _add_options(self, parser):
        parser.add_argument(
            "-t",
            "--traced-module",
            action="append",
            metavar="MODULE",
            help="restrict the trace to this module, repeat for several (default: every module)",
        )
        parser.add_argument(
            "-s",
            "--start",
            required=True,
            help="function triggering the trace, until it returns: symbol, module!symbol, module!0xoffset or 0xabsolute",
        )
        parser.add_argument(
            "-m",
            "--multi-run",
            action="store_true",
            help="trace every call (one file per call) instead of only the first one",
        )

    def _initialize(self, parser, options, args):
        self.traced_modules = options.traced_module
        self.start_spec = options.start
        self.multi_run = options.multi_run

    def _needs_target(self):
        return True

    def _start(self):
        process_name = self._device.get_process_by_pid(self._target_pid).name
        self.trace_prefix = f"{process_name}_{int(time.time())}"
        os.makedirs(TRACES_DIR, exist_ok=True)

        try:
            agent_src = self.compile_js_agent()
        except frida.InvalidArgumentError:
            self.fail_and_exit("Cannot compile agent.ts")
            return

        self.script = self._session.create_script(agent_src)
        # Add frida_tools --debug support
        self._on_script_created(self.script)
        self.script.on("message", self.on_message)
        self.script.load()

        arch = self.agent.arch()
        if arch not in SUPPORTED_ARCHS:
            self.fail_and_exit(f"Process architecture {arch} is not supported")
            return

        try:
            self.agent.trace(
                self.traced_modules,
                self.start_spec,
                not self.multi_run,
                bundle_multiple_c_files(f"{arch}.c", "common.c"),
            )
        except frida.RPCException as exc:
            self.fail_and_exit(f"Cannot start tracing: {str(exc).splitlines()[0]}")
            return

        # resume the process if it was spawned suspended (frida_tool -f)
        self._resume()
        self._update_status("Tracing... CTRL+C to stop")

    def compile_js_agent(self) -> str:
        def on_compiler_diagnostics(diagnostics: list[dict]):
            for diagnostic in diagnostics:
                self._print(format_diagnostic(diagnostic, ASSETS_DIR))

        compiler = frida.Compiler()
        compiler.on("diagnostics", on_compiler_diagnostics)
        return compiler.build(
            os.path.join(ASSETS_DIR, "agent.ts"),
            project_root=ASSETS_DIR,
            type_check="none",
        )

    def fail_and_exit(self, message: str):
        self._update_status(message)
        if self._spawned_pid is not None:
            self._device.kill(self._spawned_pid)
        self._exit(1)

    def _stop(self):
        if self.script is None:
            return

        try:
            self.agent.end()
            self.script.unload()
        except frida.InvalidOperationError:
            pass  # process already gone

        self.script = None

    def build_trace_path(self, tid: int, call: int) -> str:
        filename = f"{self.trace_prefix}_{tid}_{call}.trace"
        return os.path.join(TRACES_DIR, filename)

    def on_message(self, msg: dict, data: bytes | None):
        if msg["type"] == "error":
            self._print(f"Script error: {msg.get('stack', msg['description'])}")
            return

        payload = msg["payload"]
        if payload["id"] == "exception":
            self.script.post({"type": "exception_ack"})
            return

        path = self.build_trace_path(payload["tid"], payload["call"])
        if payload["id"] == "start":
            self._print(f"New trace: {path}")
            with open(path, "wb") as fd:
                fd.write(build_trace_header(payload["registers"], payload["modules"]))
            return

        if payload["id"] == "end":
            self._print(f"Trace done: {path}")
            return

        # payload['id'] == 'trace'
        with open(path, "ab") as fd:
            fd.write(data)


def build_trace_header(registers: str, modules: list[dict]) -> bytes:
    header = "FRINET-TRACE 1\n" + registers
    for module in modules:
        module_name = module["name"].replace(" ", "_")
        header += f"module {module_name} {module['start']} {module['end']}\n"
    header += "end\n"
    return header.encode("utf-8")


def main():
    TraceApplication().run()


if __name__ == "__main__":
    main()
