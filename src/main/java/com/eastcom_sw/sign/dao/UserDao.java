/**
 * 
 */
package com.eastcom_sw.sign.dao;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.annotation.Resource;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.stereotype.Repository;

import com.eastcom_sw.sign.entity.User;

/**
 * @author cason
 * 
 */
@Repository
public class UserDao {
	@Resource
	private JdbcTemplate jdbcTemplate;

	/**
	 * 根据用户名取用户对象
	 * @param username
	 * @return
	 */
	public User loadUser(final String username) {
		System.out.println("username=" + username);
		String sql = "select * from od_user u where u.username_=?";

		return jdbcTemplate.query(sql, new PreparedStatementSetter() {
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setString(1, username);
			}
		}, new ResultSetExtractor() {
			public Object extractData(ResultSet rs) throws SQLException,
					DataAccessException {
				User u = new User();

				while (rs.next()) {
					u.setId(rs.getString("id_"));
					u.setUsername(rs.getString("username_"));
					u.setPassword(rs.getString("password_"));
				}
				return u;
			}
		});
	}
}
