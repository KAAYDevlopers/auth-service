package com.abw12.absolutefitness.authservice.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

public class Msg91Service {
    @Autowired
    private RestTemplate restTemplate;

    @Value("${msg91.authkey}")
    private String authKey;

    public ResponseEntity<?> sendOtp(String mobile, String templateId) {
        if (!isValidIndianMobileNumber(mobile)) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Invalid mobile number format");
            return ResponseEntity.badRequest().body(errorResponse);
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("Param1", "value1");
        requestBody.put("Param2", "value2");
        requestBody.put("Param3", "value3");

        String url = "https://control.msg91.com/api/v5/otp";

        // Building the request with URI variables for query parameters
        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
        Map<String, String> uriVariables = new HashMap<>();
        uriVariables.put("template_id", templateId);
        uriVariables.put("mobile", mobile);
        uriVariables.put("authkey", authKey);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    url + "?template_id={template_id}&mobile={mobile}&authkey={authkey}",
                    HttpMethod.POST, entity, String.class, uriVariables);
            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Error calling MSG91 API: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }


    private boolean isValidIndianMobileNumber(String mobileNumber) {
        String regex = "^[6-9]\\d{9}$";
        return mobileNumber.matches(regex);
    }
}
