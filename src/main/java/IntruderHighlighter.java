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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IntruderHighlighter implements ContextMenuItemsProvider
{
    private static final String MENU_TITLE = "Intruder Highlighter";
    private static final String ACTION_LABEL = "Highlight rows that match Grep terms";

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
        "111111"
    );

    private static final List<HighlightColor> HIGHLIGHT_PALETTE = List.of(
        HighlightColor.RED,
        HighlightColor.ORANGE,
        HighlightColor.YELLOW,
        HighlightColor.GREEN,
        HighlightColor.CYAN,
        HighlightColor.BLUE,
        HighlightColor.PINK,
        HighlightColor.MAGENTA,
        HighlightColor.GRAY
    );

    private static final Pattern MATCH_NOTE_PATTERN = Pattern.compile("(?i)^(\\d+)x\\s+match:\\s*(.*)$");

    private static final boolean DEBUG_ENABLED = true;

    private final Logging logging;
    private final List<String> configuredExpressions;
    private final List<String> configuredExpressionsLower;
    private final Map<String, HighlightColor> colorAssignments = new HashMap<>();
    private int nextColorIndex;

    public IntruderHighlighter(Logging logging)
    {
        this(logging, DEFAULT_GREP_EXPRESSIONS);
    }

    public IntruderHighlighter(Logging logging, List<String> grepExpressions)
    {
        this.logging = logging;
        this.configuredExpressions = List.copyOf(grepExpressions);
        List<String> lower = new ArrayList<>();
        for (String expression : configuredExpressions)
        {
            lower.add(expression.toLowerCase(Locale.ROOT));
        }
        this.configuredExpressionsLower = lower;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        if (!event.isFrom(InvocationType.INTRUDER_ATTACK_RESULTS))
        {
            return Collections.emptyList();
        }

        List<HttpRequestResponse> requestResponses = event.selectedRequestResponses();
        if (requestResponses.isEmpty())
        {
            return Collections.emptyList();
        }

        List<HttpRequestResponse> rowsToHighlight = List.copyOf(requestResponses);

        JMenu intruderMenu = new JMenu(MENU_TITLE);
        JMenuItem highlightItem = new JMenuItem(ACTION_LABEL);
        highlightItem.addActionListener(e -> highlightMatches(rowsToHighlight));
        intruderMenu.add(highlightItem);

        return List.of(intruderMenu);
    }

    private void highlightMatches(List<HttpRequestResponse> rows)
    {
        List<HttpRequestResponse> validRows = new ArrayList<>();
        List<Map<String, Integer>> rowMatchCounts = new ArrayList<>();
        for (HttpRequestResponse row : rows)
        {
            if (!row.hasResponse())
            {
                continue;
            }

            Map<String, Integer> matchCounts = countMatches(row.response().bodyToString());
            validRows.add(row);
            rowMatchCounts.add(matchCounts);
        }

        if (validRows.isEmpty())
        {
            logging.logToOutput("Intruder highlighter found no responses to analyze.");
            return;
        }

        Map<HttpRequestResponse, List<String>> rowsToExpressions = new HashMap<>();
        Set<String> triggeredExpressions = new LinkedHashSet<>();

        for (String expression : configuredExpressions)
        {
            Map<Integer, Integer> frequency = new HashMap<>();
            for (Map<String, Integer> counts : rowMatchCounts)
            {
                int occurrences = counts.getOrDefault(expression, 0);
                frequency.merge(occurrences, 1, Integer::sum);
            }

            if (frequency.size() <= 1)
            {
                continue; // all rows have identical counts
            }

            int totalRows = rowMatchCounts.size();
            Map.Entry<Integer, Integer> majorityEntry = frequency.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .orElseThrow();
            int majorityCount = majorityEntry.getKey();
            int majorityFrequency = majorityEntry.getValue();

            logDebug("Expression '%s' frequency=%s majority=%d (%d rows) totalRows=%d", expression,
                frequency, majorityCount, majorityFrequency, totalRows);

            if (majorityFrequency <= totalRows / 2)
            {
                continue; // no strict majority
            }

            for (int i = 0; i < validRows.size(); i++)
            {
                int occurrences = rowMatchCounts.get(i).getOrDefault(expression, 0);
                if (occurrences != majorityCount)
                {
                    logDebug("Row #%d flagged for '%s': occurrences=%d vs majority=%d",
                        i + 1, expression, occurrences, majorityCount);

                    rowsToExpressions
                        .computeIfAbsent(validRows.get(i), ignored -> new ArrayList<>())
                        .add(expression);
                    triggeredExpressions.add(expression);
                }
            }
        }

        int highlighted = 0;
        for (Map.Entry<HttpRequestResponse, List<String>> entry : rowsToExpressions.entrySet())
        {
            HttpRequestResponse row = entry.getKey();
            List<String> expressions = entry.getValue();
            if (expressions.isEmpty())
            {
                continue;
            }

            HighlightColor color = colorAssignments.computeIfAbsent(expressions.get(0), this::allocateNextColor);
            Annotations annotations = row.annotations();
            annotations.setHighlightColor(color);
            annotations.setNotes(buildMatchNote(annotations.notes(), expressions));
            highlighted++;
            logDebug("Applying color %s to row for expressions %s", color.displayName(), expressions);
        }

        if (highlighted > 0)
        {
            logging.logToOutput("Intruder highlighter marked " + highlighted + " row(s) for expressions: " +
                String.join(", ", triggeredExpressions) + ".");
        }
        else
        {
            logging.logToOutput("Intruder highlighter found no anomalies for configured expressions.");
        }
    }

    private String buildMatchNote(String existingNote, List<String> matches)
    {
        if (matches.isEmpty())
        {
            return existingNote == null ? "" : existingNote;
        }

        NoteState state = parseNoteState(existingNote);
        Set<String> combined = new LinkedHashSet<>(state.expressions);
        combined.addAll(matches);

        int nextOrdinal = state.updateCount + 1;
        String base = "match: " + String.join(", ", combined);

        if (nextOrdinal > 1)
        {
            return nextOrdinal + "x " + base;
        }

        return base;
    }

    private NoteState parseNoteState(String existingNote)
    {
        if (existingNote == null || existingNote.isBlank())
        {
            return new NoteState(0, List.of());
        }

        String trimmed = existingNote.trim();
        int updateCount = 0;
        String body = trimmed;

        Matcher matcher = MATCH_NOTE_PATTERN.matcher(trimmed);
        if (matcher.matches())
        {
            updateCount = Integer.parseInt(matcher.group(1));
            body = matcher.group(2).trim();
        }
        else if (trimmed.toLowerCase(Locale.ROOT).startsWith("match:"))
        {
            updateCount = 1;
            body = trimmed.substring(trimmed.indexOf(':') + 1).trim();
        }
        else
        {
            return new NoteState(0, List.of());
        }

        List<String> expressions = new ArrayList<>();
        if (!body.isEmpty())
        {
            for (String part : body.split("\\s*,\\s*"))
            {
                if (!part.isBlank())
                {
                    expressions.add(part);
                }
            }
        }

        return new NoteState(updateCount, expressions);
    }

    private Map<String, Integer> countMatches(String response)
    {
        Map<String, Integer> matches = new HashMap<>();
        if (response == null || response.isBlank())
        {
            return matches;
        }

        String normalized = response.toLowerCase(Locale.ROOT);
        for (int i = 0; i < configuredExpressions.size(); i++)
        {
            String expression = configuredExpressions.get(i);
            String lowerExpression = configuredExpressionsLower.get(i);
            if (lowerExpression.isEmpty())
            {
                continue;
            }

            int occurrences = countOccurrences(normalized, lowerExpression);
            if (occurrences > 0)
            {
                matches.put(expression, occurrences);
            }
        }

        return matches;
    }

    private int countOccurrences(String text, String term)
    {
        int occurrences = 0;
        int index = 0;
        while ((index = text.indexOf(term, index)) != -1)
        {
            occurrences++;
            index += Math.max(term.length(), 1);
        }

        return occurrences;
    }

    private void logDebug(String format, Object... args)
    {
        if (!DEBUG_ENABLED)
        {
            return;
        }

        logging.logToOutput("[DEBUG] " + String.format(format, args));
    }

    private HighlightColor allocateNextColor(String expression)
    {
        HighlightColor color = HIGHLIGHT_PALETTE.get(nextColorIndex % HIGHLIGHT_PALETTE.size());
        nextColorIndex++;
        return color;
    }

    private static final class NoteState
    {
        private final int updateCount;
        private final List<String> expressions;

        private NoteState(int updateCount, List<String> expressions)
        {
            this.updateCount = updateCount;
            this.expressions = expressions;
        }
    }
}
