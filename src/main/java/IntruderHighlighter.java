import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public class IntruderHighlighter implements ContextMenuItemsProvider {
    private static final String MENU_TITLE = "Intruder Highlighter";
    private static final String ACTION_LABEL = "Highlight rows that match built-in list";

    private static final List<String> DEFAULT_GREP_EXPRESSIONS = List.of(
            "error",
            "exception",
            "illegal",
            "invalid",
            "fail",
            "stack",
            "access",
            "directory",
            "file",
            "not found",
            "unknown",
            "uid=",
            "c:\\",
            "varchar",
            "ODBC",
            "SQL",
            "quotation mark",
            "syntax",
            "ORA-",
            "111111");

    private static final List<HighlightColor> HIGHLIGHT_PALETTE = List.of(
            HighlightColor.RED,
            HighlightColor.ORANGE,
            HighlightColor.YELLOW,
            HighlightColor.GREEN,
            HighlightColor.CYAN,
            HighlightColor.BLUE,
            HighlightColor.PINK,
            HighlightColor.MAGENTA,
            HighlightColor.GRAY);

    private static final Pattern MATCHES_BLOCK_PATTERN = Pattern.compile("\\s*\\[matches:\\s*[^\\]]*\\]\\s*", Pattern.CASE_INSENSITIVE);

    private static final boolean DEBUG_ENABLED = true;

    private final Logging logging;
    private final List<String> configuredExpressions;
    private final List<String> configuredExpressionsLower;
    private final Map<String, HighlightColor> colorAssignments = new HashMap<>();
    private int nextColorIndex;

    public IntruderHighlighter(Logging logging) {
        this(logging, DEFAULT_GREP_EXPRESSIONS);
    }

    public IntruderHighlighter(Logging logging, List<String> grepExpressions) {
        this.logging = logging;
        this.configuredExpressions = List.copyOf(grepExpressions);
        List<String> lower = new ArrayList<>();
        for (String expression : configuredExpressions) {
            lower.add(expression.toLowerCase(Locale.ROOT));
        }
        this.configuredExpressionsLower = lower;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (!event.isFrom(InvocationType.INTRUDER_ATTACK_RESULTS)) {
            return Collections.emptyList();
        }

        List<HttpRequestResponse> requestResponses = event.selectedRequestResponses();
        if (requestResponses.isEmpty()) {
            return Collections.emptyList();
        }

        List<HttpRequestResponse> rowsToHighlight = List.copyOf(requestResponses);

        JMenu intruderMenu = new JMenu(MENU_TITLE);
        JMenuItem highlightItem = new JMenuItem(ACTION_LABEL);
        highlightItem.addActionListener(e -> highlightMatches(rowsToHighlight));
        intruderMenu.add(highlightItem);

        return List.of(intruderMenu);
    }

    private void highlightMatches(List<HttpRequestResponse> rows) {
        List<HttpRequestResponse> validRows = new ArrayList<>();
        List<Map<String, Integer>> rowMatchCounts = new ArrayList<>();
        Map<HttpRequestResponse, Map<String, Integer>> rowCountsByRow = new HashMap<>();
        for (HttpRequestResponse row : rows) {
            if (!row.hasResponse()) {
                continue;
            }

            Map<String, Integer> matchCounts = countMatches(row.response().bodyToString());
            validRows.add(row);
            rowMatchCounts.add(matchCounts);
            rowCountsByRow.put(row, matchCounts);
        }

        if (validRows.isEmpty()) {
            logging.logToOutput("Intruder highlighter found no responses to analyze.");
            return;
        }

        Map<HttpRequestResponse, Set<String>> rowsToExpressions = new HashMap<>();
        Set<String> triggeredExpressions = new LinkedHashSet<>();

        for (String expression : configuredExpressions) {
            Map<Integer, Integer> frequency = new HashMap<>();
            for (Map<String, Integer> counts : rowMatchCounts) {
                int occurrences = counts.getOrDefault(expression, 0);
                frequency.merge(occurrences, 1, Integer::sum);
            }

            if (frequency.size() <= 1) {
                continue; // all rows have identical counts
            }

            int totalRows = rowMatchCounts.size();
            Map.Entry<Integer, Integer> majorityEntry = frequency.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .orElseThrow();
            int majorityCount = majorityEntry.getKey();
            int majorityFrequency = majorityEntry.getValue();

            logDebug("Expression '%s' frequency=%s majorityCount=%d majorityFrequency=%d totalRows=%d",
                    expression, frequency, majorityCount, majorityFrequency, totalRows);

            for (int i = 0; i < validRows.size(); i++) {
                int occurrences = rowMatchCounts.get(i).getOrDefault(expression, 0);
                if (occurrences == majorityCount) {
                    continue;
                }

                logDebug("Row #%d flagged for '%s': occurrences=%d vs majorityCount=%d",
                        i + 1, expression, occurrences, majorityCount);

                rowsToExpressions
                        .computeIfAbsent(validRows.get(i), ignored -> new LinkedHashSet<>())
                        .add(expression);
                triggeredExpressions.add(expression);
            }
        }

        int highlighted = 0;
        for (Map.Entry<HttpRequestResponse, Set<String>> entry : rowsToExpressions.entrySet()) {
            HttpRequestResponse row = entry.getKey();
            List<String> expressions = new ArrayList<>(entry.getValue());
            if (expressions.isEmpty()) {
                continue;
            }

            String comboKey = String.join("|", expressions);
            HighlightColor color = colorAssignments.computeIfAbsent(comboKey, this::allocateNextColor);
            Annotations annotations = row.annotations();
            Map<String, Integer> counts = rowCountsByRow.getOrDefault(row, Collections.emptyMap());
            annotations.setHighlightColor(color);
            annotations.setNotes(buildMatchNote(annotations.notes(), expressions, counts));
            highlighted++;
            logDebug("Applying color %s to row for expressions %s", color.displayName(), expressions);
        }

        if (highlighted > 0) {
            logging.logToOutput("Intruder highlighter marked " + highlighted + " row(s) for expressions: " +
                    String.join(", ", triggeredExpressions) + ".");
        } else {
            logging.logToOutput("Intruder highlighter found no anomalies for configured expressions.");
        }
    }

    private String buildMatchNote(String existingNote, List<String> matches, Map<String, Integer> counts) {
        if (matches.isEmpty()) {
            return removeMatchesSegment(existingNote);
        }

        List<String> entries = new ArrayList<>();
        for (String expression : matches) {
            int occurrences = counts.getOrDefault(expression, 0);
            entries.add(occurrences + "x " + expression);
        }

        String block = "[matches: " + String.join(", ", entries) + "]";
        String cleaned = removeMatchesSegment(existingNote);
        if (cleaned.isBlank()) {
            return block;
        }

        return cleaned.trim() + " " + block;
    }

    private String removeMatchesSegment(String note) {
        if (note == null || note.isBlank()) {
            return "";
        }

        return MATCHES_BLOCK_PATTERN.matcher(note).replaceAll("").trim();
    }

    private Map<String, Integer> countMatches(String response) {
        Map<String, Integer> matches = new HashMap<>();
        if (response == null || response.isBlank()) {
            return matches;
        }

        String normalized = response.toLowerCase(Locale.ROOT);
        for (int i = 0; i < configuredExpressions.size(); i++) {
            String expression = configuredExpressions.get(i);
            String lowerExpression = configuredExpressionsLower.get(i);
            if (lowerExpression.isEmpty()) {
                continue;
            }

            int occurrences = countOccurrences(normalized, lowerExpression);
            if (occurrences > 0) {
                matches.put(expression, occurrences);
            }
        }

        return matches;
    }

    private int countOccurrences(String text, String term) {
        int occurrences = 0;
        int index = 0;
        while ((index = text.indexOf(term, index)) != -1) {
            occurrences++;
            index += Math.max(term.length(), 1);
        }

        return occurrences;
    }

    private void logDebug(String format, Object... args) {
        if (!DEBUG_ENABLED) {
            return;
        }

        logging.logToOutput("[DEBUG] " + String.format(format, args));
    }

    private HighlightColor allocateNextColor(String expression) {
        HighlightColor color = HIGHLIGHT_PALETTE.get(nextColorIndex % HIGHLIGHT_PALETTE.size());
        nextColorIndex++;
        return color;
    }

}
