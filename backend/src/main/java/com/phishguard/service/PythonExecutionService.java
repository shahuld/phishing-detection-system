package com.phishguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
public class PythonExecutionService {

    private static final Logger logger = LoggerFactory.getLogger(PythonExecutionService.class);

    private final ObjectMapper objectMapper = new ObjectMapper();

@Value("${python.script.path:../python/ml/phishing_detector_fixed.py}")
    private String pythonScriptPath;

    @Value("${python.executable:python3}")
    private String pythonExecutable;

    /**
     * Execute Python script and return parsed JSON.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> executeScript(String scriptPath, String... args) {
        try {
            List<String> command = new ArrayList<>();
            command.add(pythonExecutable);

            // Resolve absolute path
            Path script = Paths.get(scriptPath);
            if (!script.isAbsolute()) {
                script = Paths.get("").toAbsolutePath().resolve(scriptPath);
            }

            command.add(script.toString());
            command.addAll(Arrays.asList(args));

            logger.info("Executing Python: {}", String.join(" ", command));

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);

            Process process = pb.start();

            StringBuilder output = new StringBuilder();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {

                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            // ✅ Increased timeout
            boolean finished = process.waitFor(60, TimeUnit.SECONDS);

            if (!finished) {
                process.destroyForcibly();
                return createErrorResponse("Python script timeout");
            }

            int exitCode = process.exitValue();
            logger.info("Python exit code: {}", exitCode);

            String rawOutput = output.toString().trim();

            // 🔥 IMPORTANT DEBUG LOG
            logger.info("RAW PYTHON OUTPUT:\n{}", rawOutput);

            if (exitCode != 0) {
                return createErrorResponse("Python error: " + rawOutput);
            }

            if (rawOutput.isEmpty()) {
                return createErrorResponse("Empty output from Python");
            }

            // 🔥 FIXED: Extract last complete JSON block
            // Find last complete JSON (from last { to matching })
            String[] lines = rawOutput.split("\n");
            StringBuilder jsonBuilder = new StringBuilder();
            int braceCount = 0;
            boolean inJson = false;
            for (String line : lines) {
                if (line.trim().startsWith("{")) {
                    if (!inJson) {
                        jsonBuilder = new StringBuilder();
                        inJson = true;
                    }
                    jsonBuilder.append(line.trim()).append("\n");
                    braceCount = 1;
                } else if (inJson) {
                    jsonBuilder.append(line.trim()).append("\n");
                    for (char c : line.toCharArray()) {
                        if (c == '{') braceCount++;
                        else if (c == '}') {
                            braceCount--;
                            if (braceCount == 0) {
                                break;
                            }
                        }
                    }
                    if (braceCount == 0) {
                        break;
                    }
                }
            }
            rawOutput = jsonBuilder.toString().trim();

            logger.info("CLEAN JSON OUTPUT:\n{}", rawOutput);

            try {
                return objectMapper.readValue(rawOutput, Map.class);
            } catch (Exception e) {
                logger.error("JSON parse failed: {}", rawOutput);
                return createErrorResponse("Invalid JSON from Python");
            }

        } catch (Exception e) {
            logger.error("Execution error: {}", e.getMessage());
            return createErrorResponse("Execution error: " + e.getMessage());
        }
    }

    /**
     * URL phishing detection
     */
    public Map<String, Object> detectUrl(String url) {
        try {
            return executeScript(pythonScriptPath, url);
        } catch (Exception e) {
            logger.error("URL detection error: {}", e.getMessage());
            return createErrorResponse(e.getMessage());
        }
    }

    /**
     * Certificate detection
     */
    public Map<String, Object> detectCertificate(Map<String, Object> certData) {
        try {
            String inputJson = objectMapper.writeValueAsString(certData);

            File tempFile = File.createTempFile("cert_", ".json");
            Files.writeString(tempFile.toPath(), inputJson);

            try {
                return executeScript(
                        pythonScriptPath,
                        "--type", "certificate",
                        "--input", tempFile.getAbsolutePath()
                );
            } finally {
                tempFile.delete();
            }

        } catch (Exception e) {
            logger.error("Certificate detection error: {}", e.getMessage());
            return createErrorResponse(e.getMessage());
        }
    }

    /**
     * Domain detection
     */
    public Map<String, Object> detectDomain(Map<String, Object> domainData) {
        try {
            String domain = String.valueOf(domainData.get("domain"));

            // ✅ FIX: sanitize bad input like "[object Object]"
            if (domain == null || domain.contains("[object")) {
                return createErrorResponse("Invalid domain input");
            }

            Map<String, Object> cleanData = new HashMap<>();
            cleanData.put("domain", domain);
            cleanData.put("domain_age_days", 365); // fallback

            String inputJson = objectMapper.writeValueAsString(cleanData);

            File tempInputFile = File.createTempFile("phish_domain_", ".json");
            try {
                Files.writeString(tempInputFile.toPath(), inputJson);

                String scriptPath = pythonScriptPath;

                Map<String, Object> result = executeScript(
                        scriptPath,
                        "--type", "domain",
                        "--input", tempInputFile.getAbsolutePath()
                );

                logger.info("Domain ML result: {}", result);
                return result;

            } finally {
                tempInputFile.delete();
            }

        } catch (Exception e) {
            logger.error("Error detecting domain: {}", e.getMessage());
            return createErrorResponse(e.getMessage());
            }
    }

    /**
     * Standard error response
     */
    private Map<String, Object> createErrorResponse(String message) {
        Map<String, Object> error = new HashMap<>();
        error.put("result", "error");
        error.put("message", message);
        error.put("confidence", 0);
        return error;
    }
}

