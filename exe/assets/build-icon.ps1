[CmdletBinding()]
param(
    [string]$PngPath,
    [string]$IcoPath
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($PngPath)) { $PngPath = Join-Path $PSScriptRoot 'icon.png' }
if ([string]::IsNullOrWhiteSpace($IcoPath)) { $IcoPath = Join-Path $PSScriptRoot 'scanner.ico' }
Add-Type -AssemblyName System.Drawing

$source = [System.Drawing.Bitmap]::FromFile((Resolve-Path -LiteralPath $PngPath))
$sizes = @(256, 128, 64, 48, 32, 16)
$frames = [System.Collections.Generic.List[byte[]]]::new()
try {
    foreach ($size in $sizes) {
        $frame = [System.Drawing.Bitmap]::new($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $graphics = [System.Drawing.Graphics]::FromImage($frame)
        try {
            $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
            $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
            $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $destinationRect = [System.Drawing.Rectangle]::new(0, 0, $size, $size)
            $graphics.DrawImage($source, $destinationRect, 0, 0, $source.Width, $source.Height, [System.Drawing.GraphicsUnit]::Pixel)

            $memory = [System.IO.MemoryStream]::new()
            try {
                $frame.Save($memory, [Drawing.Imaging.ImageFormat]::Png)
                $frames.Add($memory.ToArray())
            }
            finally { $memory.Dispose() }
        }
        finally {
            $graphics.Dispose()
            $frame.Dispose()
        }
    }
}
finally { $source.Dispose() }

$outputPath = [IO.Path]::GetFullPath($IcoPath)
$parent = Split-Path -Parent $outputPath
if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$stream = [System.IO.File]::Open($outputPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
$writer = [System.IO.BinaryWriter]::new($stream)
try {
    $writer.Write([UInt16]0)
    $writer.Write([UInt16]1)
    $writer.Write([UInt16]$sizes.Count)
    $offset = 6 + (16 * $sizes.Count)
    for ($i = 0; $i -lt $sizes.Count; $i++) {
        $dimension = if ($sizes[$i] -eq 256) { [byte]0 } else { [byte]$sizes[$i] }
        $writer.Write($dimension)
        $writer.Write($dimension)
        $writer.Write([byte]0)
        $writer.Write([byte]0)
        $writer.Write([UInt16]1)
        $writer.Write([UInt16]32)
        $writer.Write([UInt32]$frames[$i].Length)
        $writer.Write([UInt32]$offset)
        $offset += $frames[$i].Length
    }
    foreach ($frameBytes in $frames) { $writer.Write($frameBytes) }
}
finally {
    $writer.Dispose()
    $stream.Dispose()
}

Write-Host "Wrote multi-size icon: $outputPath"
