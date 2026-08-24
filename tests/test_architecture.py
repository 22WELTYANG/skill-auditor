from skill_auditor import cli, report_builder, scanner
from skill_auditor.errors import ScanError


def test_cli_preserves_legacy_scanner_and_report_imports():
    assert cli.ScanError is ScanError
    assert cli.scan_text is scanner.scan_text
    assert cli.validate_skill_directory is scanner.validate_skill_directory
    assert cli.build_report is report_builder.build_report
    assert cli.build_recursive_report is report_builder.build_recursive_report
    assert cli.render_report is report_builder.render_report


def test_cli_is_only_the_command_router_for_scan_and_report_layers():
    assert scanner.scan_text.__module__ == "skill_auditor.scanner"
    assert report_builder.build_report.__module__ == "skill_auditor.report_builder"
    assert report_builder.build_collection_report.__module__ == (
        "skill_auditor.report_builder"
    )
