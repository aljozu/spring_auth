package com.authExample.demoAuth.repository;

import com.authExample.demoAuth.models.ERole;
import com.authExample.demoAuth.models.Rol;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Rol, Long> {
    Optional<Rol> findByName(ERole name);
}
