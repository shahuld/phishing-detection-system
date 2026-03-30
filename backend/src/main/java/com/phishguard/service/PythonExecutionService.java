package com.phishguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Service for executing Python ML scripts directly.
 * This replaces the Flask API integration.
 */
@Service
public class PythonExecutionService {
    
    private static final Logger logger = LoggerFactory.getLogger(PythonExecutionService.class);
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    @Value("${python.script.path:../python ml/phishing_detector.py}")
    private String pythonScriptPath;
    
    @Value("${python.executable:python3}")
    private String pythonExecutable;
    
    /**
     * Execute a Python script with the given arguments and return JSON output.
     * 
     * @param scriptPath Path to the Python script (relative to backend directory)
     * @param args Command line arguments to pass to the script
     * @return Map containing the JSON response from Python
     */
    public Map<String, Object> executeScript(String scriptPath, String... args) {
        try {
            // Build the command
            java.util.List<String> command = new java.util.ArrayList<>();
            command.add(pythonExecutable);
            
            // Add script path
            if (!scriptPath.startsWith("/")) {
                // Resolve relative path from backend directory
                Path basePath = Paths.get("").toAbsolutePath();
                scriptPath = basePath.resolve(scriptPath).toString();
            }
            command.add(scriptPath);
            
            // Add additional arguments
            for (String arg : args) {
                command.add(arg);
            }
            
            logger.info("Executing Python script: {}", String.join(" ", command));
            
            // Execute the process
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true);
            
            Process process = processBuilder.start();
            
            // Read output
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }
            
            // Wait for completion
            boolean finished = process.waitFor(30, TimeUnit.SECONDS);
            
            if (!finished) {
                process.destroyForcibly();
                logger.warn("Python script timed out");
                return createErrorResponse("Script execution timed out");
            }
            
            int exitCode = process.exitValue();
            logger.info("Python script exited with code: {}", exitCode);
            
            if (exitCode != 0) {
                logger.warn("Python script error: {}", output.toString());
                return createErrorResponse("Script execution failed: " + output.toString());
            }
            
            // Parse JSON output
            String outputStr = output.toString().trim();
            if (outputStr.isEmpty()) {
                return createErrorResponse("Empty output from script");
            }
            
            // Try to parse as JSON
            try {
                return objectMapper.readValue(outputStr, Map.class);
            } catch (Exception e) {
                // If not JSON, wrap in a response
                Map<String, Object> result = new HashMap<>();
                result.put("output", outputStr);
                result.put("result", "success");
                return result;
            }
            
        } catch (IOException e) {
            logger.error("IO error executing Python script: {}", e.getMessage());
            return createErrorResponse("IO error: " + e.getMessage());
        } catch (InterruptedException e) {
            logger.error("Python script interrupted: {}", e.getMessage());
            Thread.currentThread().interrupt();
            return createErrorResponse("Script interrupted: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Error executing Python script: {}", e.getMessage());
            return createErrorResponse("Error: " + e.getMessage());
        }
    }
    
    /**
     * Execute URL phishing detection using Python ML.
     * 
     * @param url The URL to check
     * @return Map containing detection result
     */
    public Map<String, Object> detectUrlPhishing(String url) {
        try {
            // Create a temporary input file with the URL
            Map<String, String> input = new HashMap<>();
            input.put("url", url);
            
            String inputJson = objectMapper.writeValueAsString(input);
            
            // Write input to temp file
            File tempInputFile = File.createTempFile("phish_input_", ".json");
            try {
                Files.writeString(tempInputFile.toPath(), inputJson);
                
                // Execute script with input file
                return executeWithInputFile(tempInputFile.getAbsolutePath(), "--url");
            } finally {
                tempInputFile.delete();
            }
        } catch (Exception e) {
            logger.error("Error in URL detection: {}", e.getMessage());
            return createErrorResponse("Error detecting URL: " + e.getMessage());
        }
    }
    
    /**
     * Execute detection with input from a file.
     */
    private Map<String, Object> executeWithInputFile(String inputFile, String... extraArgs) throws Exception {
        java.util.List<String> command = new java.util.ArrayList<>();
        command.add(pythonExecutable);
        
        // Resolve script path
        String resolvedScriptPath = pythonScriptPath;
        if (!pythonScriptPath.startsWith("/")) {
            Path basePath = Paths.get("").toAbsolutePath();
            resolvedScriptPath = basePath.resolve(pythonScriptPath).toString();
        }
        command.add(resolvedScriptPath);
        
        // Add extra args
        command.add("--input");
        command.add(inputFile);
        
        for (String arg : extraArgs) {
            command.add(arg);
        }
        
        logger.info("Executing: {}", String.join(" ", command));
        
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        
        Process process = processBuilder.start();
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        
        boolean finished = process.waitFor(30, TimeUnit.SECONDS);
        
        if (!finished) {
            process.destroyForcibly();
            return createErrorResponse("Script timed out");
        }
        
        String outputStr = output.toString().trim();
        if (outputStr.isEmpty()) {
            return createErrorResponse("Empty output");
        }
        
        try {
            return objectMapper.readValue(outputStr, Map.class);
        } catch (Exception e) {
            Map<String, Object> result = new HashMap<>();
            result.put("output", outputStr);
            return result;
        }
    }
    
    /**
     * Simple URL detection that parses output from the ML script.
     * This is a simplified version that works with the existing script structure.
     */
    public Map<String, Object> detectUrl(String url) {
        try {
            // Get the backend directory path
            Path backendPath = Paths.get("").toAbsolutePath();
            Path pythonMlPath = backendPath.resolve("..").resolve("python ml");
            Path modelsPath = backendPath.resolve("..").resolve("models");
            
            // Use Python -c to execute inline code
            String pythonCode = String.format(
                "import sys; sys.path.insert(0, '%s'); " +
                "from phishing_detector import PhishingDetectorML; " +
                "import json; " +
                "detector = PhishingDetectorML(model_dir='%s'); " +
                "result = detector.check_url('%s'); " +
                "print(json.dumps(result))",
                pythonMlPath.toString().replace("\\", "\\\\"),
                modelsPath.toString().replace("\\", "\\\\"),
                url.replace("'", "''")
            );
            
            java.util.List<String> command = java.util.Arrays.asList(
                pythonExecutable, "-c", pythonCode
            );
            
            logger.info("Executing URL detection for: {} from directory: {}", url, backendPath);
            
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.directory(backendPath.toFile());
            processBuilder.redirectErrorStream(true);
            
            Process process = processBuilder.start();
            
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line);
                }
            }
            
            boolean finished = process.waitFor(30, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                logger.warn("Python script timed out for URL: {}", url);
                return createErrorResponse("Timeout");
            }
            
            int exitCode = process.exitValue();
            String outputStr = output.toString().trim();
            logger.info("Python output for URL {}: exitCode={}, output={}", url, exitCode, outputStr);
            
            if (exitCode != 0 || outputStr.isEmpty()) {
                logger.warn("Python script failed for URL: {}, falling back to heuristic", url);
                return createErrorResponse("Python execution failed");
            }
            
            return objectMapper.readValue(outputStr, Map.class);
            
        } catch (Exception e) {
            logger.error("Error detecting URL {}: {}", url, e.getMessage());
            return createErrorResponse(e.getMessage());
        }
    }
    
    /**
     * Simple certificate detection.
     */
    public Map<String, Object> detectCertificate(Map<String, Object> certData) {
        try {
            String jsonCert = objectMapper.writeValueAsString(certData)
                .replace("'", "''");
            
            String pythonCode = String.format(
                "import sys; sys.path.insert(0, '.'); " +
                "from phishing_detector import PhishingDetectorML; " +
                "import json; " +
                "detector = PhishingDetectorML(model_dir='../models'); " +
                "result = detector.check_certificate(%s); " +
                "print(json.dumps(result))",
                jsonCert
            );
            
            java.util.List<String> command = java.util.Arrays.asList(
                pythonExecutable, "-c", pythonCode
            );
            
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.directory(Paths.get("").toAbsolutePath().toFile());
            processBuilder.redirectErrorStream(true);
            
            Process process = processBuilder.start();
            
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line);
                }
            }
            
            process.waitFor(30, TimeUnit.SECONDS);
            
            String outputStr = output.toString().trim();
            if (outputStr.isEmpty()) {
                return createErrorResponse("Empty output");
            }
            
            return objectMapper.readValue(outputStr, Map.class);
            
        } catch (Exception e) {
            logger.error("Error detecting certificate: {}", e.getMessage());
            return createErrorResponse(e.getMessage());
        }
    }
    
    /**
     * Simple domain detection.
     */
    public Map<String, Object> detectDomain(Map<String, Object> domainData) {
        try {
            String jsonDomain = objectMapper.writeValueAsString(domainData)
                .replace("'", "''");
            
            String pythonCode = String.format(
                "import sys; sys.path.insert(0, '.'); " +
                "from phishing_detector import PhishingDetectorML; " +
                "import json; " +
                "detector = PhishingDetectorML(model_dir='../models'); " +
                "result = detector.check_domain(%s); " +
                "print(json.dumps(result))",
                jsonDomain
            );
            
            java.util.List<String> command = java.util.Arrays.asList(
                pythonExecutable, "-c", pythonCode
            );
            
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.directory(Paths.get("").toAbsolutePath().toFile());
            processBuilder.redirectErrorStream(true);
            
            Process process = processBuilder.start();
            
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line);
                }
            }
            
            process.waitFor(30, TimeUnit.SECONDS);
            
            String outputStr = output.toString().trim();
            if (outputStr.isEmpty()) {
                return createErrorResponse("Empty output");
            }
            
            return objectMapper.readValue(outputStr, Map.class);
            
        } catch (Exception e) {
            logger.error("Error detecting domain: {}", e.getMessage());
            return createErrorResponse(e.getMessage());
        }
    }
    
    private Map<String, Object> createErrorResponse(String message) {
        Map<String, Object> error = new HashMap<>();
        error.put("result", "error");
        error.put("message", message);
        error.put("confidence", 0);
        return error;
    }
}

