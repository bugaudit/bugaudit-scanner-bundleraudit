package me.shib.bugaudit.scanner.ruby.bundleraudit;

import me.shib.bugaudit.commons.BugAuditContent;
import me.shib.bugaudit.commons.BugAuditException;
import me.shib.bugaudit.scanner.*;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public final class BundlerAuditScanner extends BugAuditScanner {

    private static transient final String cveBaseURL = "https://nvd.nist.gov/vuln/detail/";
    private static transient final Lang lang = Lang.Ruby;
    private static transient final String tool = "BundlerAudit";
    private static transient final File bundlerAuditOutput = new File("bugaudit-bundleraudit-result.txt");

    public BundlerAuditScanner() {
        this.getBugAuditScanResult().addKey("Vulnerable-Dependency");
    }

    private static int getPriorityNumberForName(String priorityName) {
        switch (priorityName) {
            case "High":
                return 2;
            case "Medium":
                return 3;
            case "Low":
                return 4;
            case "Urgent":
                return 1;
            case "Critical":
                return 1;
            default:
                return 2;
        }
    }

    private void addBugForContent(String gemVulnerabilityContent) {
        String advisory = "";
        String url = "";
        String descriptionTitle = "";
        String solution = "";
        String gemName = "";
        String gemVersion = "";
        int priority = 3;
        String[] split = gemVulnerabilityContent.split("Solution: ");
        if (split.length == 2) {
            solution = split[1].replace("\n", " ").trim();
        }
        split = split[0].split("Title: ");
        if (split.length == 2) {
            descriptionTitle = split[1].replace("\n", " ").trim();
        }
        split = split[0].split("URL: ");
        if (split.length == 2) {
            url = split[1].replace("\n", " ").trim();
        }
        split = split[0].split("Criticality: ");
        if (split.length == 2) {
            priority = getPriorityNumberForName(split[1].replace("\n", " ").trim());
        }
        split = split[0].split("Advisory: ");
        if (split.length == 2) {
            advisory = split[1].replace("\n", " ").trim();
        }
        split = split[0].split("Version: ");
        if (split.length == 2) {
            gemVersion = split[1].replace("\n", " ").trim();
        }
        split = split[0].split("Name: ");
        if (split.length == 2) {
            gemName = split[1].replace("\n", " ").trim();
        }
        String title = "Vulnerable Gem (" + advisory + ") - " + gemName +
                " in repo - " + getBugAuditScanResult().getRepo();
        Bug bug = getBugAuditScanResult().newBug(title, priority);
        bug.setDescription(new BugAuditContent(getDescription(gemName, gemVersion, descriptionTitle, url, solution, advisory)));
        bug.addKey(gemName);
        bug.addKey(advisory);
        getBugAuditScanResult().addBug(bug);
    }

    private String getDescription(String gemName, String gemVersion, String descriptionTitle, String url, String solution, String advisory) {
        StringBuilder description = new StringBuilder();
        description.append("A vulnerable gem (**").append(gemName)
                .append("-").append(gemVersion)
                .append("**) was found to be used in the repository ");
        description.append("**[").append(getBugAuditScanResult().getRepo()).append("](")
                .append(getBugAuditScanResult().getRepo().getUrl()).append(")**.\n");
        try {
            description.append("\n**[").append(advisory).append("](").append(getUrlForCVE(advisory)).append("):**");
        } catch (BugAuditException e) {
            description.append("\n**[").append(advisory).append("](").append(url).append("):**");
        }
        if (descriptionTitle != null && !descriptionTitle.isEmpty()) {
            description.append("\n * **Description:** ").append(descriptionTitle);
        }
        if (url != null && !url.isEmpty()) {
            description.append("\n * **Reference:** [").append(url).append("]");
        }
        if (solution != null && !solution.isEmpty()) {
            description.append("\n * **Solution:** ").append(solution);
        }
        return description.toString();
    }

    private void parseOutputContentToResult(String content) throws BugAuditException {
        String[] lines = content.split("\n");
        if (!lines[lines.length - 1].equalsIgnoreCase("No vulnerabilities found")) {
            List<String> vulnGemLines = new ArrayList<>();
            for (String line : lines) {
                if (!line.startsWith("Insecure Source URI found")) {
                    vulnGemLines.add(line);
                }
            }
            StringBuilder vulnerabilityContent = new StringBuilder();
            int i = 0;
            while ((i < vulnGemLines.size()) && !vulnGemLines.get(i).equalsIgnoreCase("Vulnerabilities found!")) {
                if (!vulnGemLines.get(i).isEmpty()) {
                    vulnerabilityContent.append(vulnGemLines.get(i)).append("\n");
                } else {
                    addBugForContent(vulnerabilityContent.toString());
                    vulnerabilityContent = new StringBuilder();
                }
                i++;
            }
        }
    }

    private String bundlerAuditExecutor(String command) throws BugAuditException {
        CommandExecutor commandExecutor = new CommandExecutor();
        commandExecutor.enableConsoleOutput(true);
        commandExecutor.runCommand(command);
        String response = commandExecutor.getConsoleOutput();
        if (response.contains("command not found") || response.contains("is currently not installed")) {
            throw new BugAuditException("Install npm before proceeding");
        }
        return response;
    }

    private String readFromFile(File file) throws IOException {
        StringBuilder contentBuilder = new StringBuilder();
        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;
        while ((line = br.readLine()) != null) {
            contentBuilder.append(line).append("\n");
        }
        br.close();
        return contentBuilder.toString();
    }

    private void writeToFile(String content, File file) throws FileNotFoundException {
        PrintWriter pw = new PrintWriter(file);
        pw.append(content);
        pw.close();
    }

    private void runBundlerAudit() throws BugAuditException, FileNotFoundException {
        System.out.println("Running RetireJS...");
        String bundlerAuditResponse = bundlerAuditExecutor("bundle-audit");
        writeToFile(bundlerAuditResponse, bundlerAuditOutput);
    }

    private void installBundlerAudit() throws BugAuditException {
        bundlerAuditExecutor("gem install bundle-audit");
    }

    private void updateBundlerAuditDatabase() throws BugAuditException {
        bundlerAuditExecutor("bundle-audit update");
    }

    private void parseBundlerAuditResult() throws BugAuditException, IOException {
        String resultContent = readFromFile(bundlerAuditOutput);
        parseOutputContentToResult(resultContent);
    }

    @Override
    public BugAuditScannerConfig getDefaultScannerConfig() {
        return new BundlerAuditConfig();
    }

    @Override
    protected Lang getLang() {
        return lang;
    }

    @Override
    public String getTool() {
        return tool;
    }

    @Override
    public void scan() throws Exception {
        if (!isParserOnly()) {
            bundlerAuditOutput.delete();
            installBundlerAudit();
            updateBundlerAuditDatabase();
            runBundlerAudit();
        }
        parseBundlerAuditResult();
    }
}
