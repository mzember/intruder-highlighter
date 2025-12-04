import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Extension implements BurpExtension
{
    @Override
    public void initialize(MontoyaApi montoyaApi)
    {
        montoyaApi.extension().setName("Intruder Highlighter");
        montoyaApi.userInterface().registerContextMenuItemsProvider(
            new IntruderHighlighter(montoyaApi.logging())
        );
    }
}
