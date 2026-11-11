from setuptools import Extension, setup


setup(
    ext_modules=[
        Extension(
            "valider._native",
            sources=["valider/_native.cpp"],
            language="c++",
            extra_compile_args=["-std=c++17"],
        )
    ]
)
