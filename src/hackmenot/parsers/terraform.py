"""Terraform HCL parser using python-hcl2."""

from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any, IO

import hcl2

from hackmenot.parsers.base import BaseParser, ParseResult


@dataclass
class TerraformResourceInfo:
    """Information about a Terraform resource block."""

    resource_type: str
    name: str
    config: dict[str, Any] = field(default_factory=dict)
    line: int = 0


@dataclass
class TerraformVariableInfo:
    """Information about a Terraform variable definition."""

    name: str
    default: Any = None
    sensitive: bool = False
    line: int = 0


@dataclass
class TerraformLocalInfo:
    """Information about a Terraform local value."""

    name: str
    value: Any = None
    line: int = 0


@dataclass
class TerraformParseResult:
    """Result of parsing a Terraform file."""

    file_path: Path = field(default_factory=lambda: Path("<string>"))
    has_error: bool = False
    error_message: str | None = None
    resources: list[TerraformResourceInfo] = field(default_factory=list)
    variables: list[TerraformVariableInfo] = field(default_factory=list)
    locals: list[TerraformLocalInfo] = field(default_factory=list)


class TerraformParser(BaseParser):
    """Parser for Terraform HCL files using python-hcl2."""

    SUPPORTED_EXTENSIONS = {".tf", ".tfvars"}

    def parse_file(self, file_path: Path) -> TerraformParseResult:
        """Parse a Terraform file from disk."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                suffix = file_path.suffix
                result = self._parse_hcl(f, suffix)
                result.file_path = file_path
                return result
        except FileNotFoundError as e:
            return TerraformParseResult(
                file_path=file_path,
                has_error=True,
                error_message=f"File not found: {e}",
            )
        except Exception as e:
            return TerraformParseResult(
                file_path=file_path,
                has_error=True,
                error_message=str(e),
            )

    def parse_string(
        self, source: str, filename: str = "<string>"
    ) -> TerraformParseResult:
        """Parse Terraform HCL source code string."""
        file_path = Path(filename)
        suffix = file_path.suffix if file_path.suffix else ".tf"

        try:
            file_obj = StringIO(source)
            result = self._parse_hcl(file_obj, suffix)
            result.file_path = file_path
            return result
        except Exception as e:
            return TerraformParseResult(
                file_path=file_path,
                has_error=True,
                error_message=str(e),
            )

    def _parse_hcl(self, file_obj: IO[str], suffix: str) -> TerraformParseResult:
        """Internal method to parse HCL content.

        Args:
            file_obj: File-like object containing HCL content.
            suffix: File extension (.tf or .tfvars) to determine parsing mode.

        Returns:
            TerraformParseResult with extracted resources, variables, and locals.
        """
        try:
            parsed = hcl2.load(file_obj)
        except Exception as e:
            return TerraformParseResult(
                has_error=True,
                error_message=f"HCL parse error: {e}",
            )

        resources: list[TerraformResourceInfo] = []
        variables: list[TerraformVariableInfo] = []
        locals_list: list[TerraformLocalInfo] = []

        # Handle .tfvars files - they contain just key-value pairs
        if suffix == ".tfvars":
            for key, value in parsed.items():
                # Treat tfvars entries as locals
                locals_list.append(
                    TerraformLocalInfo(
                        name=key,
                        value=value[0] if isinstance(value, list) and value else value,
                        line=1,  # hcl2 doesn't provide line numbers
                    )
                )
            return TerraformParseResult(
                resources=resources,
                variables=variables,
                locals=locals_list,
            )

        # Handle .tf files - full HCL with blocks
        # Parse resource blocks
        if "resource" in parsed:
            for resource_block in parsed["resource"]:
                for resource_type, resource_instances in resource_block.items():
                    for resource_name, config in resource_instances.items():
                        resources.append(
                            TerraformResourceInfo(
                                resource_type=resource_type,
                                name=resource_name,
                                config=config,
                                line=1,  # hcl2 doesn't provide line numbers directly
                            )
                        )

        # Parse variable blocks
        if "variable" in parsed:
            for var_block in parsed["variable"]:
                for var_name, var_config in var_block.items():
                    default_value = var_config.get("default")
                    # Handle the case where default might be a list
                    if isinstance(default_value, list) and len(default_value) == 1:
                        default_value = default_value[0]

                    sensitive = var_config.get("sensitive", False)
                    # Handle boolean in list format
                    if isinstance(sensitive, list) and len(sensitive) == 1:
                        sensitive = sensitive[0]

                    variables.append(
                        TerraformVariableInfo(
                            name=var_name,
                            default=default_value,
                            sensitive=bool(sensitive),
                            line=1,
                        )
                    )

        # Parse locals blocks
        if "locals" in parsed:
            for locals_block in parsed["locals"]:
                for local_name, local_value in locals_block.items():
                    # Handle value possibly being in a list
                    if isinstance(local_value, list) and len(local_value) == 1:
                        local_value = local_value[0]

                    locals_list.append(
                        TerraformLocalInfo(
                            name=local_name,
                            value=local_value,
                            line=1,
                        )
                    )

        # Parse data source blocks (treat as special resources for now)
        if "data" in parsed:
            for data_block in parsed["data"]:
                for data_type, data_instances in data_block.items():
                    for data_name, config in data_instances.items():
                        # Mark data sources with a prefix to distinguish them
                        resources.append(
                            TerraformResourceInfo(
                                resource_type=f"data.{data_type}",
                                name=data_name,
                                config=config,
                                line=1,
                            )
                        )

        return TerraformParseResult(
            resources=resources,
            variables=variables,
            locals=locals_list,
        )
