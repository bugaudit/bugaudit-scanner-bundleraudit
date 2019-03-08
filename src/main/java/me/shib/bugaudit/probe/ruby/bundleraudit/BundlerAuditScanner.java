package me.shib.bugaudit.probe.ruby.bundleraudit;

import me.shib.bugaudit.commons.*;
import me.shib.bugaudit.probe.ProbeConfig;
import me.shib.bugaudit.probe.ProbeScanner;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class BundlerAuditScanner extends ProbeScanner {

    private static final Lang lang = Lang.Ruby;
    private static final String tool = "BundlerAudit";
    private static final File bundlerAuditOutput = new File("bundleraudit-out.txt");

    public BundlerAuditScanner() {
        this.bugAuditResult.addKey("Vulnerable-Dependency");
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
                return 3;
        }
    }

    private void addBugForContent(String gemVulnerabilityContent) throws BugAuditException {
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
                " in repo - " + bugAuditResult.getRepo();
        Bug bug = bugAuditResult.newBug(title, priority);
        bug.setDescription(new BugAuditContent(getDescription(gemName, gemVersion, descriptionTitle, url, solution, advisory)));
        bug.addKey(gemName);
        bug.addKey(advisory);
        bugAuditResult.addBug(bug);

    }

    private String getDescription(String gemName, String gemVersion, String descriptionTitle, String url, String solution, String cve) throws BugAuditException {
        StringBuilder description = new StringBuilder();
        description.append("A vulnerable gem (**").append(gemName)
                .append("-").append(gemVersion)
                .append("**) was found to be used in the repository ");
        description.append("**[").append(bugAuditResult.getRepo()).append("](")
                .append(bugAuditResult.getRepo().getUrl()).append(")**.\n");
        description.append("\n**[").append(cve).append("](").append(getUrlForCVE(cve)).append("):**");
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

    private void bundlerAuditExecutor(String command) throws BugAuditException {
        CommandExecutor commandExecutor = new CommandExecutor();
        commandExecutor.enableConsoleOutput(true);
        commandExecutor.runCommand(command);
        String response = commandExecutor.getConsoleOutput();
        if (response.contains("command not found") || response.contains("is currently not installed")) {
            throw new BugAuditException("Install npm before proceeding");
        }
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

    private void runBundlerAudit() throws BugAuditException {
        System.out.println("Running RetireJS...");
        bundlerAuditExecutor("bundle-audit > " + bundlerAuditOutput.getPath());
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
    protected ProbeConfig getDefaultProbeConfig() {
        return new BundlerAuditConfig();
    }

    @Override
    protected Lang getLang() {
        return lang;
    }

    @Override
    protected String getTool() {
        return tool;
    }

    @Override
    protected void scan() throws Exception {
        if (!parserOnly) {
            bundlerAuditOutput.delete();
            installBundlerAudit();
            updateBundlerAuditDatabase();
            runBundlerAudit();
        }
        parseBundlerAuditResult();
    }
}
