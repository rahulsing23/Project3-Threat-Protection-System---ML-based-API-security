package com.threatprotection.threat;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties
public class ThreatServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(ThreatServiceApplication.class, args);
	}

}
