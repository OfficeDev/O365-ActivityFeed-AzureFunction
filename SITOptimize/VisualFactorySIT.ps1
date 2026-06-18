<#!
.SYNOPSIS
    Visual Factory - Generates HTML dashboards from Markdown policy files.
    
.DESCRIPTION
    This script iterates through all Markdown (.md) files in the specified folder.
    It renders them to full HTML locally using PowerShell's markdown engine and wraps the result in a self-contained dashboard style sheet.
    This preserves all markdown content instead of relying on an LLM to rewrite the document.
    
.EXAMPLE
    .\VisualFactory.ps1
    Generates HTML dashboards for all .md files in the current folder (c:\PS\renew).

.EXAMPLE
    .\VisualFactory.ps1 -Force
    Force regenerates all HTML files even if they are newer than the source MD.
#>

param(
    [string]$TargetFolder = "C:\PS\sitoptimize",
    [switch]$Force = $false
)

$dashboardCss = @'
:root {
    --font-ui: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    --font-mono: 'Cascadia Code', 'Fira Code', Consolas, monospace;
    --bg-body: #f3f4f7;
    --bg-card: #ffffff;
    --bg-muted: #f7f8fb;
    --text-primary: #212936;
    --text-secondary: #667284;
    --border: #dfe3ea;
    --accent: #ff7a1a;
    --accent-strong: #d55d00;
    --accent-soft: #fff1e6;
    --code-bg: #f8f1ec;
    --code-fg: #b74f12;
    --inline-code-bg: #fff3eb;
    --inline-code-fg: #d35d1f;
    --table-stripe: #fcfcfd;
    --quote-bg: #fff7e8;
    --quote-border: #f0ad2c;
    --section-accent: var(--accent);
    --section-soft: var(--accent-soft);
}
* { box-sizing: border-box; }
body {
    margin: 0;
    font-family: var(--font-ui);
    background: linear-gradient(180deg, #f8f9fc 0%, var(--bg-body) 100%);
    color: var(--text-primary);
    line-height: 1.6;
}
.page {
    max-width: 1600px;
    margin: 0 auto;
    padding: 22px 26px 40px;
}
.hero {
    background: transparent;
    color: var(--text-primary);
    border-radius: 0;
    padding: 0;
    margin-bottom: 18px;
    box-shadow: none;
    border: 0;
}
.hero h1 {
    margin: 0;
    font-size: 1.85rem;
    font-weight: 700;
}
.hero p {
    display: none;
    margin: 0;
    color: var(--text-secondary);
}
.content {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 24px;
    box-shadow: 0 8px 22px rgba(31, 41, 55, 0.08);
    border-top: 5px solid var(--accent);
}
h1:first-child {
    font-size: 2rem;
    margin-top: 0;
    margin-bottom: 1.25rem;
}
h1, h2, h3, h4, h5, h6 {
    color: var(--text-primary);
    scroll-margin-top: 20px;
}
h1 {
    font-size: 1.8rem;
    margin: 0 0 1rem;
}
h2 {
    margin-top: 2rem;
    padding: 1rem 1rem 0.9rem;
    background: linear-gradient(180deg, var(--section-soft) 0%, #fafbfd 100%);
    border: 1px solid var(--border);
    border-left: 0;
    border-top: 4px solid var(--section-accent);
    border-radius: 8px 8px 0 0;
    font-size: 1.25rem;
    box-shadow: none;
}
h3 {
    margin-top: 1.5rem;
    color: var(--text-secondary);
    font-size: 1.05rem;
}
p, li {
    font-size: 14px;
}
ul, ol {
    padding-left: 1.5rem;
}
hr + h2,
p + h2 {
    margin-top: 2.2rem;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0 1.5rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    display: block;
    overflow-x: auto;
    background: #fff;
}
thead {
    background: var(--bg-muted);
}
th, td {
    padding: 12px 14px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: top;
    font-size: 13px;
    white-space: nowrap;
}
th {
    color: var(--section-accent);
}
tbody tr:nth-child(even) {
    background: var(--table-stripe);
}
tbody tr:hover {
    background: #fff8f2;
}
tr:last-child td {
    border-bottom: none;
}
code {
    font-family: var(--font-mono);
    background: var(--inline-code-bg);
    color: var(--inline-code-fg);
    padding: 2px 6px;
    border-radius: 6px;
    border: 1px solid #e6d3bf;
}
pre {
    font-family: var(--font-mono);
    background: var(--code-bg);
    color: var(--code-fg);
    padding: 16px;
    border-radius: 8px;
    overflow-x: auto;
    border: 1px solid #f0d5c5;
    white-space: pre;
}
blockquote {
    margin: 1rem 0;
    padding: 0.9rem 1rem;
    background: var(--quote-bg);
    border-left: 4px solid var(--quote-border);
    color: #713f12;
    border-radius: 8px;
}
strong {
    color: #1f2937;
}
.section-accented {
    position: relative;
}
.section-accented::after {
    content: "";
    position: absolute;
    left: 0;
    right: 0;
    bottom: -1px;
    height: 1px;
    background: linear-gradient(90deg, var(--section-accent), transparent 75%);
    opacity: 0.45;
}
hr {
    border: 0;
    border-top: 1px solid var(--border);
    margin: 2rem 0;
}
a {
    color: var(--accent);
    text-decoration-thickness: 1px;
    text-underline-offset: 2px;
}
img {
    max-width: 100%;
}
'@

$sectionAccentScript = @'
<script>
(function () {
    const palette = [
        { accent: '#ff7a1a', soft: '#fff1e6' },
        { accent: '#2563eb', soft: '#eaf2ff' },
        { accent: '#0f766e', soft: '#e8f7f5' },
        { accent: '#8b5cf6', soft: '#f2ebff' },
        { accent: '#c2410c', soft: '#fff0e8' },
        { accent: '#be185d', soft: '#fdebf3' },
        { accent: '#3f7d20', soft: '#eef8e8' }
    ];

    function hashText(value) {
        let hash = 0;
        for (let i = 0; i < value.length; i++) {
            hash = ((hash << 5) - hash) + value.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash);
    }

    const sectionHeadings = document.querySelectorAll('main h2');
    sectionHeadings.forEach((heading) => {
        const color = palette[hashText(heading.textContent.trim()) % palette.length];
        heading.classList.add('section-accented');
        heading.style.setProperty('--section-accent', color.accent);
        heading.style.setProperty('--section-soft', color.soft);
    });
})();
</script>
'@

function Convert-MarkdownToDashboardHtml {
    param(
        [string]$MarkdownContent,
        [string]$Title
    )

    $converted = ConvertFrom-Markdown -InputObject $MarkdownContent
    $bodyHtml = $converted.Html
    if (-not $bodyHtml) {
        throw "Markdown conversion returned no HTML."
    }

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$Title</title>
<style>
$dashboardCss
</style>
</head>
<body>
    <div class="page">
        <section class="hero">
            <h1>$Title</h1>
            <p>Deterministic markdown rendering with full content preservation.</p>
        </section>
        <main class="content">
$bodyHtml
        </main>
    </div>
    $sectionAccentScript
</body>
</html>
"@
}

# ---------------------------------------------------------
# EXECUTION LOOP
# ---------------------------------------------------------

$files = Get-ChildItem -Path $TargetFolder -Filter "*.md"

Write-Host "Found $($files.Count) MD files in $TargetFolder..." -ForegroundColor Cyan

foreach ($file in $files) {
    $baseName = $file.BaseName
    $htmlPath = Join-Path $TargetFolder "$baseName.html"
    
    # Skip if HTML exists and is newer than MD (unless -Force)
    if (Test-Path $htmlPath) {
        $mdTime = $file.LastWriteTime
        $htmlTime = (Get-Item $htmlPath).LastWriteTime
        
        if ($htmlTime -gt $mdTime -and -not $Force) {
            Write-Host " [SKIP] $baseName.html is up to date." -ForegroundColor DarkGray
            continue
        }
    }
    
    Write-Host " [PROC] Generating Dashboard for: $baseName..." -NoNewline -ForegroundColor Yellow
    
    # 1. Read MD Content
    $mdContent = Get-Content $file.FullName -Raw -Encoding UTF8
    
    # Normalize line endings only, preserve all Unicode (emojis, special chars needed for rendering)
    $mdContent = $mdContent -replace "`r`n", "`n" -replace "`r", "`n"
    
    # 1b. Convert internal markdown links to HTML file references
    # Find all markdown links like [text](file.md) and convert to [text](file.html)
    $mdContent = $mdContent -replace '\[([^\]]+)\]\(([^/)]+\.md)\)', '[$1]($2.html)'
    
    try {
        $htmlContent = Convert-MarkdownToDashboardHtml -MarkdownContent $mdContent -Title "Sensitive Information Type optimization"

        $htmlContent | Set-Content -Path $htmlPath -Encoding UTF8 -NoNewline
        Write-Host " DONE" -ForegroundColor Green
    }
    catch {
        Write-Host " ERROR" -ForegroundColor Red
        Write-Error "Failed to process $baseName : $_"
    }
}

Write-Host "`nAll operations complete." -ForegroundColor Cyan