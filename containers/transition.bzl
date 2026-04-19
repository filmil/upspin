def _multi_arch_transition_impl(settings, attr):
    return [
        {"//command_line_option:platforms": "@rules_go//go/toolchain:linux_amd64"},
        {"//command_line_option:platforms": "@rules_go//go/toolchain:linux_arm64"},
    ]

multi_arch_transition = transition(
    implementation = _multi_arch_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _multi_arch_image_impl(ctx):
    return [DefaultInfo(files = depset(transitive = [dep[DefaultInfo].files for dep in ctx.attr.image]))]

multi_arch_image = rule(
    implementation = _multi_arch_image_impl,
    attrs = {
        "image": attr.label(cfg = multi_arch_transition),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)
