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
import java.util.List;
import java.util.Locale;
import java.util.Map;
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

    private static final Pattern MATCH_NOTE_PATTERN = Pattern.compile("^(\\d+)x match: .*", Pattern.CASE_INSENSITIVE);

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
        int highlighted = 0;
        for (HttpRequestResponse row : rows)
        {
            if (!row.hasResponse())
            {
                continue;
            }

            List<String> matches = findMatches(row);
            if (matches.isEmpty())
            {
                continue;
            }

            String leadingExpression = matches.get(0);
            HighlightColor color = colorAssignments.computeIfAbsent(leadingExpression, this::allocateNextColor);
            Annotations annotations = row.annotations();
            annotations.setHighlightColor(color);
            annotations.setNotes(buildMatchNote(annotations.notes(), matches));
            highlighted++;
        }

        logging.logToOutput("Intruder highlighter marked " + highlighted + " row(s) that matched [" +
            String.join(", ", configuredExpressions) + "].");
    }

    private HighlightColor allocateNextColor(String expression)
    {
        HighlightColor color = HIGHLIGHT_PALETTE.get(nextColorIndex % HIGHLIGHT_PALETTE.size());
        nextColorIndex++;
        return color;
    }

    private List<String> findMatches(HttpRequestResponse row)
    {
        String body = row.response().bodyToString();
        if (body == null)
        {
            return Collections.emptyList();
        }

        String normalized = body.toLowerCase(Locale.ROOT);
        List<String> matches = new ArrayList<>();
        for (int i = 0; i < configuredExpressionsLower.size(); i++)
        {
            if (normalized.contains(configuredExpressionsLower.get(i)))
            {
                matches.add(configuredExpressions.get(i));
            }
        }

        return matches;
    }

    private String buildMatchNote(String existingNote, List<String> matches)
    {
        if (matches.isEmpty())
        {
            return existingNote == null ? "" : existingNote;
        }

        String matchFragment = "match: " + String.join(" ", matches);
        if (existingNote == null || existingNote.isBlank())
        {
            return matchFragment;
        }

        Matcher matcher = MATCH_NOTE_PATTERN.matcher(existingNote.trim());
        if (matcher.matches())
        {
            int count = Integer.parseInt(matcher.group(1));
            return (count + 1) + "x " + matchFragment;
        }

        return "2x " + matchFragment;
    }
}
