package com.dpi.config;

import com.dpi.model.DpiStats;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DpiConfig {

    @Bean
    public DpiStats dpiStats() {
        return new DpiStats();
    }
}
