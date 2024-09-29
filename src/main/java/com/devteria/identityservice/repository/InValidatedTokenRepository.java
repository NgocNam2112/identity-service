package com.devteria.identityservice.repository;

import com.devteria.identityservice.entity.InValidatedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface InValidatedTokenRepository extends JpaRepository<InValidatedToken, String> {

}
