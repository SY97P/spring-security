package com.tangerine.springsecurity.user;

import jakarta.persistence.*;

@Entity
@Table(name = "group_permission")
public class GroupPermission {

    @Id
    @Column(name = "id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "group_id", referencedColumnName = "id")
    private Group group;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "permission_id", referencedColumnName = "id")
    private Permission permission;

    public Long getId() {
        return id;
    }

    public Group getGroup() {
        return group;
    }

    public Permission getPermission() {
        return permission;
    }

}
