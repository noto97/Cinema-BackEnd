package org.sid.cinema.dao;


import org.sid.cinema.entities.Cinema;
import org.sid.cinema.entities.Seance;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.web.bind.annotation.CrossOrigin;

import java.util.Date;

@RepositoryRestResource
@CrossOrigin("*")

public interface SeanceRepository extends JpaRepository<Seance,Long> {
}
