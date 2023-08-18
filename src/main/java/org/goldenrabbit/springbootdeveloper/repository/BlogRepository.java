package org.goldenrabbit.springbootdeveloper.repository;

import org.goldenrabbit.springbootdeveloper.domain.Article;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BlogRepository extends JpaRepository<Article, Long> {
}
