import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.Collections;
import java.util.List;

public class IntruderHighlighter implements ContextMenuItemsProvider
{
    private static final String MENU_TITLE = "Intruder Highlighter";
    private static final String ACTION_LABEL = "Highlight alternating rows";
    private static final HighlightColor HIGHLIGHT_COLOR = HighlightColor.CYAN;

    private final Logging logging;

    public IntruderHighlighter(Logging logging)
    {
        this.logging = logging;
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
        highlightItem.addActionListener(e -> highlightAlternatingRows(rowsToHighlight));
        intruderMenu.add(highlightItem);

        return List.of(intruderMenu);
    }

    private void highlightAlternatingRows(List<HttpRequestResponse> rows)
    {
        for (int i = 0; i < rows.size(); i++)
        {
            HighlightColor color = (i % 2 == 0) ? HIGHLIGHT_COLOR : HighlightColor.NONE;
            rows.get(i).annotations().setHighlightColor(color);
        }

        logging.logToOutput("Intruder highlighter marked " + rows.size() + " selected row(s).");
    }
}
