# Intruder Highlighter (Burp Suite Extension)

## Problem
Burp Intruder produces long result tables when Grep-matching is enabled, and each pattern becomes a column that the analyst must sort and inspect manually, one-by-one. (Testing turns into a game: "spot the checkbox").

## Solution
In Burp Intruder results window, this **extensions highlights only the interesting** results for you: the outliars. It highlights rows by different colors and adds reasoning to comments. By using Burp's **View filter** ("show only highlighted items" or "items with notes"), only interesting results are displayed.

## Installation
1. Build the extension with `./gradlew jar` (or download a compiled JAR from [the releases](https://github.com/mzember/intruder-highlighter/releases) under "Assets").
2. Open Burp, go to **Extensions > Installed > Add**, select the generated JAR from `build/libs/`, and follow the prompts.
3. Optional reinstall: In the list of installed extensions, toggle the checkbox off and on. (Ctrl/⌘+click works but misbehaves.)

## Usage
1. Launch an Intruder attack.~~with the desired Grep matches enabled so the results table gains a button column for each expression.~~
2. Select the rows you want to evaluate (Ctrl+A to grab them all), right-click any row, and choose **Extensions > Intruder Highlighter > Highlight rows that match built-in list**.

## Output
1. Rows whose expression counts differ from the majority will be recolored; they also receive a `[matches: …]` note with counts.
1. See debug logging output if you need to understand why a particular expression was flagged: in Extensions, in the bottom part under "Output" tab.

## Limitations
- **Patterns are built-in! Any grep-match patterns you add to Intruder attack settings are not visible to the extension via API.**
- The extension can only see the user’s current selection because the Montoya API does not expose the full Intruder table; you must select the rows before invoking the highlight action.
- Does not handle HTTP status codes yet, neither times of responses.

## Details
Color assignments are per-combination-of-patterns so you can see which match is responsible. The matching is case-insensitive, ignores headers, and exposes debug output by default to explain every decision.

Gradle (build system) handles the Montoya API dependency.
