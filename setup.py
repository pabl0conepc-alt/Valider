from pathlib import Path
import subprocess

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

ROOT = Path(__file__).resolve().parent


class BuildNativeExtensions(build_ext):
    def run(self):
        subprocess.run(
            ["cargo", "build", "--release", "--manifest-path", str(ROOT / "rust" / "Cargo.toml")],
            cwd=ROOT,
            check=True,
        )
        for extension in self.extensions:
            if extension.name == "valider._native":
                extension.extra_objects = [
                    str(ROOT / "rust" / "target" / "release" / "libvalider_rust.a")
                ]
        super().run()

setup(
    ext_modules=[
        Extension(
            "valider._native",
            sources=["valider/_native.cpp"],
            language="c++",
            extra_compile_args=["-std=c++17"],
        )
    ],
    cmdclass={"build_ext": BuildNativeExtensions},
)
