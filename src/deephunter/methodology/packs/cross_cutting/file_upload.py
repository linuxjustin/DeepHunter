"""File Upload Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch, DecisionTreeNode, MethodologyPack, PackCategory,
    PackChecklist, PackPlannerRule,
)

PACK = MethodologyPack(
    name="File Upload",
    version="1.0.0", category=PackCategory.CROSS_CUTTING,
    description="Expert methodology for testing file upload functionality. Covers extension bypass, content-type spoofing, path traversal, stored XSS, PHAR deserialization, polyglot files, and SSI/SHTML injection.",
    attack_surface_areas=["file upload", "input validation", "rce"],
    investigation_priority=90,
    related_packs=["REST API", "Business Logic"],

    checklists=[
        PackChecklist(
            objective="Test extension validation bypass",
            description="Test all known extension bypass techniques against file upload validation.",
            procedure="1. Test double extension (.jpg.php, .php.jpg)\n2. Test null byte injection (.php%00.jpg)\n3. Test case variation (.PhP, .pHp, .PHP5, .phtml)\n4. Test alternative extensions (.shtml, .pht, .php7, .php8)\n5. Test .htaccess and .user.ini upload\n6. Test .svg (XSS via SVG)\n7. Test .xml (XXE via XML upload)\n8. Test trailing characters (.php., .php , .php.php)\n9. Test executable extensions (.exe, .sh, .pl, .py, .jsp)",
            priority="critical", difficulty="medium",
            required_evidence=["Executable file uploaded successfully"],
            expected_result="Extension validation bypass assessed",
            bug_classes=[BugClass.RCE, BugClass.XSS],
            tags=["upload", "extension"],
        ),
        PackChecklist(
            objective="Test MIME type/content-type validation",
            description="Test MIME type validation by spoofing Content-Type header.",
            procedure="1. Upload PHP file with Content-Type: image/jpeg\n2. Upload file with Content-Type: application/octet-stream\n3. Test multipart boundary manipulation\n4. Check if MIME type is checked from magic bytes or just header\n5. Upload polyglot GIF+PHP file\n6. Test image resize processing for RCE (ImageMagick/GraphicsMagick)\n7. Test server-side image library vulnerabilities",
            priority="critical", difficulty="medium",
            required_evidence=["Spoofed MIME type bypassing validation"],
            expected_result="MIME validation bypass assessed",
            bug_classes=[BugClass.RCE],
            tags=["upload", "mime"],
        ),
        PackChecklist(
            objective="Test path traversal in filename",
            description="Test filename path traversal to write files outside the intended directory.",
            procedure="1. Use filename: ../../../etc/cron.d/malicious\n2. Use URL-encoded path traversal: %2e%2e%2f, %252e%252e%252f\n3. Use OS-specific traversal: ..\\ on Windows\n4. Test with absolute paths: /var/www/html/shell.php\n5. Test symlink following\n6. Test time-of-check time-of-use (TOCTOU) on filename validation\n7. Test file overwriting (existing files)",
            priority="critical", difficulty="hard",
            required_evidence=["File written outside upload directory"],
            expected_result="Path traversal assessed",
            bug_classes=[BugClass.PATH_TRAVERSAL, BugClass.RCE],
            tags=["upload", "path traversal"],
        ),
        PackChecklist(
            objective="Test stored XSS via file upload",
            description="Test for stored cross-site scripting via uploaded files.",
            procedure="1. Upload HTML file with XSS payload\n2. Upload SVG with embedded script\n3. Upload file with XSS in filename\n4. Upload PDF with JavaScript action\n5. Upload file with XSS in EXIF/metadata\n6. Upload CSV with formula injection (=CMD, +DDE)\n7. Upload file with XSS in content-disposition filename",
            priority="high", difficulty="medium",
            required_evidence=["XSS executed from uploaded file"],
            expected_result="Stored XSS via upload assessed",
            bug_classes=[BugClass.XSS],
            tags=["upload", "xss"],
        ),
        PackChecklist(
            objective="Test polyglot file attacks",
            description="Test polyglot files that pass validation but execute as different format.",
            procedure="1. Create GIF+PHP polyglot file\n2. Create PDF+JavaScript polyglot\n3. Create JPEG+PHP polyglot (embedded PHP in EXIF/comment)\n4. Create ZIP+PHP polyglot\n5. Upload and test each polyglot for execution\n6. Test polyglot with image processing libraries\n7. Create Phar polyglot with serialized PHP objects",
            priority="critical", difficulty="hard",
            required_evidence=["Polyglot file executed as code"],
            expected_result="Polyglot file attacks assessed",
            bug_classes=[BugClass.RCE, BugClass.XSS],
            tags=["upload", "polyglot"],
        ),
        PackChecklist(
            objective="Test file size and quota limitations",
            description="Test file upload size limits, quota enforcement, and disk exhaustion.",
            procedure="1. Upload file exceeding declared max size\n2. Send chunked transfer to bypass size limits\n3. Upload multiple small files to exhaust quota\n4. Test resumable upload logic for size bypass\n5. Test compression bomb (ZIP bomb) upload\n6. Check error handling for exceeded limits",
            priority="medium", difficulty="easy",
            required_evidence=["Uploaded file exceeding limits"],
            expected_result="File size security assessed",
            bug_classes=[BugClass.DOS],
            tags=["upload", "size"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="upload-root", question="What file upload aspect to test?",
            branches=[
                DecisionTreeBranch(condition="Extension check present", conclusion="TEST: 1. Double extension 2. Case variation 3. Null byte 4. Alternative extensions (.phtml, .php5, .shtml)"),
                DecisionTreeBranch(condition="Content-type validation", conclusion="TEST: 1. Header spoofing 2. Magic byte mismatch 3. Polyglot files"),
                DecisionTreeBranch(condition="Image processing after upload", conclusion="TEST: 1. ImageTragick RCE 2. ImageMagick SSRF 3. EXIF/XMP injection 4. PNG compression bomp"),
                DecisionTreeBranch(condition="File stored with original name", conclusion="TEST: 1. Path traversal 2. Direct access 3. Stored XSS via filename"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(attack_surface="file upload", description="Prioritize extension validation bypass testing", priority_modifier=0.25, phase="input_validation"),
        PackPlannerRule(attack_surface="file upload", description="Prioritize path traversal in filename", priority_modifier=0.15, phase="input_validation"),
        PackPlannerRule(attack_surface="file upload", description="Prioritize polyglot file attacks", priority_modifier=0.15, phase="input_validation"),
    ],
    references=[
        {"source": "CWE", "id": "CWE-434", "title": "Unrestricted Upload of File with Dangerous Type"},
        {"source": "OWASP", "id": "WSTG-BUSL-01", "title": "Business Logic Testing"},
    ],
    tags=["upload", "file", "rce", "input validation"],
)
